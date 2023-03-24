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

package controllers

import (
	"context"

	ebpfv1 "bpfexporter/api/v1"
	"bpfexporter/pkg/dnsthrottling"
	oom "bpfexporter/pkg/oomprobe"
	"bpfexporter/pkg/pidtracking"
	conn "bpfexporter/pkg/streamconntrack"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// BpfExporterReconciler reconciles a BpfExporter object
type BpfExporterReconciler struct {
	K8sClient client.Client
	Scheme    *runtime.Scheme
	Logger    logr.Logger
}

//+kubebuilder:rbac:groups=ebpf.exporter.k8s.aws,resources=bpfexporters,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ebpf.exporter.k8s.aws,resources=bpfexporters/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ebpf.exporter.k8s.aws,resources=bpfexporters/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the BpfExporter object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.1/pkg/reconcile
func (r *BpfExporterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	// The resource is being created or updated
	if err := r.reconcile(ctx, req); err != nil {
		r.Logger.Info("Reconcile error, requeueing", "err", err)
		return ctrl.Result{Requeue: true}, nil
	}

	return ctrl.Result{}, nil
	//return runtime.HandleReconcileError(r.reconcile(req), r.log) //TODO
}

// SetupWithManager sets up the controller with the Manager.
func (r *BpfExporterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ebpfv1.BpfExporter{}).
		Complete(r)
}

func (r *BpfExporterReconciler) reconcile(ctx context.Context, req ctrl.Request) error {
	bpfExporter := &ebpfv1.BpfExporter{}
	if err := r.K8sClient.Get(ctx, req.NamespacedName, bpfExporter); err != nil {
		if isNotFoundErr := client.IgnoreNotFound(err); isNotFoundErr == nil {
			return r.DeletionReconciler(ctx, bpfExporter)
		}
		return err
	}

	//Get list of kernel probes and functions
	bpfExporterSpec := bpfExporter.Spec

	for _, probe := range bpfExporterSpec.Probes {
		r.Logger.Info("Reconciling BPF Exported Policy for", "Probe name:", probe.ProbeName)
		switch probe.ProbeName {
		case "oom_kill_process":
			//Get all pods and namespace
			podsToWatch := make(map[ebpfv1.DeploymentInfo]bool)
			for _, pod := range probe.Deployment {
				r.Logger.Info("Got policy", "Pod name:", pod.DeploymentName)
				r.Logger.Info("Got policy", "Pod namespace:", pod.DeploymentNamespace)
				podsToWatch[pod] = true
			}
			if len(podsToWatch) > 0 {
				oom.AttachOOMProbe(r.Logger)
			}

		case "conn_track_stream":
			//conn.AttachStreamProbe(r.Logger)
			conn.AttachKprobegoBPF(r.Logger)

		case "pid_usage":
			pidtracking.AttachPidProbe(r.Logger)

		case "capture_dns_throttle":
			dnsthrottling.CaptureDNSlimits(r.Logger)

		default:
			r.Logger.Info("Invalid Probe Name...!!")
		}

	}

	return nil
}

func (r *BpfExporterReconciler) DeletionReconciler(ctx context.Context, cr *ebpfv1.BpfExporter) error {
	r.Logger.Info("Got delete")
	return nil
}
