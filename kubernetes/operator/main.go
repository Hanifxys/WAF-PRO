package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	wafPolicyGVR = schema.GroupVersionResource{
		Group:    "wafpro.io",
		Version:  "v1alpha1",
		Resource: "wafpolicies",
	}
	wafAppGVR = schema.GroupVersionResource{
		Group:    "wafpro.io",
		Version:  "v1alpha1",
		Resource: "wafapplications",
	}
	mgmtAPIURL = os.Getenv("MANAGEMENT_API_URL")
)

func main() {
	log.Println("Starting WAF-PRO Kubernetes Operator...")

	if mgmtAPIURL == "" {
		mgmtAPIURL = "http://management-api:8082/api/v1/kubernetes/sync"
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatalf("Failed to build kubeconfig: %v", err)
		}
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create dynamic client: %v", err)
	}

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynClient, 30*time.Second, metav1.NamespaceAll, nil)

	policyInformer := factory.ForResource(wafPolicyGVR).Informer()
	appInformer := factory.ForResource(wafAppGVR).Informer()

	policyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { syncResource(obj, "WAFPolicy") },
		UpdateFunc: func(oldObj, newObj interface{}) { syncResource(newObj, "WAFPolicy") },
		DeleteFunc: func(obj interface{}) { syncResource(obj, "WAFPolicy") }, // Minimal handler for demo
	})

	appInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { syncResource(obj, "WAFApplication") },
		UpdateFunc: func(oldObj, newObj interface{}) { syncResource(newObj, "WAFApplication") },
		DeleteFunc: func(obj interface{}) { syncResource(obj, "WAFApplication") },
	})

	stopCh := make(chan struct{})
	defer close(stopCh)

	log.Println("Starting informers...")
	factory.Start(stopCh)
	factory.WaitForCacheSync(stopCh)

	log.Println("WAF-PRO Operator is running and watching CRDs.")
	<-stopCh
}

func syncResource(obj interface{}, kind string) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}

	payload := map[string]interface{}{
		"kind": kind,
		"name": u.GetName(),
		"namespace": u.GetNamespace(),
		"spec": u.Object["spec"],
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal %s: %v", kind, err)
		return
	}

	log.Printf("Syncing %s %s/%s to Management API...", kind, u.GetNamespace(), u.GetName())
	
	resp, err := http.Post(mgmtAPIURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to send sync request to Management API: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("Successfully synced %s %s/%s", kind, u.GetNamespace(), u.GetName())
	} else {
		log.Printf("Management API returned status %d for %s %s/%s", resp.StatusCode, kind, u.GetNamespace(), u.GetName())
	}
}
