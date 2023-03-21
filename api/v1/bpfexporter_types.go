/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// BpfExporterSpec defines the desired state of BpfExporter
type BpfExporterSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:Optional
	// A list of kernel probe specs.
	Probes []ProbeSpec `json:"kernelprobes"`
	// +kubebuilder:validation:Optional
	// A list of tracepoint probe specs.
	TracePointProbes []TracepointProbeSpec `json:"tracepointprobes"`
}

type ProbeSpec struct {
	// Function probe.
	FuncName string `json:"funcname"`

	// +kubebuilder:validation:Optional
	// A list of pods and pods namespace.
	Pods []PodNameNamespace `json:"pods"`
}

type PodNameNamespace struct {
	// +kubebuilder:validation:Optional
	// Pod which has to be probed.
	PodName string `json:"podname"`
	// +kubebuilder:validation:Optional
	// Pod's namespace.
	PodNamespace string `json:"podnamespace"`
}

type TracepointProbeSpec struct {
	// Function probe.
	FuncName string `json:"funcname"`

	// +kubebuilder:validation:Optional
	// A list of deployment and deployment namespace.
	Deployment []DeploymentNameNamespace `json:"deployment"`
}

type DeploymentNameNamespace struct {
	// +kubebuilder:validation:Optional
	// Deployment which has to be probed.
	DeploymentName string `json:"deploymentname"`
	// +kubebuilder:validation:Optional
	// Deployment's namespace.
	DeploymentNamespace string `json:"deploymentnamespace"`
}

// BpfExporterStatus defines the observed state of BpfExporter
type BpfExporterStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// BpfExporter is the Schema for the bpfexporters API
type BpfExporter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BpfExporterSpec   `json:"spec,omitempty"`
	Status BpfExporterStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// BpfExporterList contains a list of BpfExporter
type BpfExporterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BpfExporter `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BpfExporter{}, &BpfExporterList{})
}
