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

	"github.com/go-logr/logr"
	errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	reconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	ebpfv1 "bpfexporter/api/v1"
	//oom "bpfexporter/pkg/oomprobe"
	pidtracking "bpfexporter/pkg/pidtracking"
	conn "bpfexporter/pkg/streamconntrack"
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

	// TODO(user): your logic here
	cr := &ebpfv1.BpfExporter{}
	if err := r.K8sClient.Get(ctx, req.NamespacedName, cr); err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted
			// return and don't requeue
			r.Logger.Info("unable to get policy", "resource", cr, "err", err)
			return reconcile.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Check if the resource is being deleted
	if !cr.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.DeletionReconciler(ctx, cr)
	}
	// The resource is being created or updated
	return r.CreateOrUpdateReconciler(ctx, req, cr)

	//return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *BpfExporterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ebpfv1.BpfExporter{}).
		Complete(r)
}

func (r *BpfExporterReconciler) CreateOrUpdateReconciler(ctx context.Context, req ctrl.Request, cr *ebpfv1.BpfExporter) (ctrl.Result, error) {
	r.Logger.Info("Got create or update")
	//Get list of kernel probes and functions
	bpfExporterSpec := cr.Spec
	for _, probe := range bpfExporterSpec.Probes {
		r.Logger.Info("Got policy", "Func name:", probe.FuncName)
		switch probe.FuncName {
		/*
			case "oom_kill_process":
			//Get all pods and namespace
				podsToWatch := make(map[ebpfv1.PodNameNamespace]bool)
				for _, pod := range probe.Pods {
					r.Logger.Info("Got policy", "Pod name:", pod.PodName)
					r.Logger.Info("Got policy", "Pod namespace:", pod.PodNamespace)
					podsToWatch[pod] = true
				}
				if len(podsToWatch) > 0 {
					oom.AttachOOMProbe(r.Logger)
				}
		*/
		case "conn_track_stream":
			//conn.AttachStreamProbe(r.Logger)
			conn.AttachKprobegoBPF(r.Logger)

		default:
			r.Logger.Info("Not supported func name -- Implement it...")
		}

	}

	for _, traceprobe := range bpfExporterSpec.TracePointProbes {
		r.Logger.Info("Got policy", "Func name:", traceprobe.FuncName)
		switch traceprobe.FuncName {
		case "pid_usage":
			pidtracking.AttachPidProbe(r.Logger)
		default:
			r.Logger.Info("Not supported func name -- Implement it...")
		}
	}
	return ctrl.Result{}, nil
}

func (r *BpfExporterReconciler) DeletionReconciler(ctx context.Context, cr *ebpfv1.BpfExporter) (ctrl.Result, error) {
	r.Logger.Info("Got delete")
	return ctrl.Result{}, nil
}
