/*
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

package pushsecret

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	esapi "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	"github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	ctrlmetrics "github.com/external-secrets/external-secrets/pkg/controllers/metrics"
	"github.com/external-secrets/external-secrets/pkg/controllers/pushsecret/psmetrics"
	"github.com/external-secrets/external-secrets/pkg/controllers/secretstore"
	"github.com/external-secrets/external-secrets/pkg/provider/util/locks"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

const (
	errFailedGetSecret       = "could not get source secret"
	errPatchStatus           = "error merging"
	errGetSecretStore        = "could not get SecretStore %q, %w"
	errGetClusterSecretStore = "could not get ClusterSecretStore %q, %w"
	errSetSecretFailed       = "could not write remote ref %v to target secretstore %v: %v"
	errFailedSetSecret       = "set secret failed: %v"
	errConvert               = "could not apply conversion strategy to keys: %v"
	errUnmanagedStores       = "PushSecret %q has no managed stores to push to"
	pushSecretFinalizer      = "pushsecret.externalsecrets.io/finalizer"
)

type Reconciler struct {
	client.Client
	Log             logr.Logger
	Scheme          *runtime.Scheme
	recorder        record.EventRecorder
	RequeueInterval time.Duration
	ControllerClass string
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor("pushsecret")

	return ctrl.NewControllerManagedBy(mgr).
		For(&esapi.PushSecret{}).
		Complete(r)
}

func totalReconcileDuration(reconcileLabels map[string]string, start time.Time) {
	duration := float64(time.Since(start).Seconds())
    psmetrics.GetGaugeVec(psmetrics.PushSecretReconcileDurationKey).
        With(labels).
        Set(duration)
}

func (r *Reconciler) fetchPushSecret(ctx context.Context, req ctrl.Request) (esapi.PushSecret, error) {
	var ps esapi.PushSecret
	err := r.Get(ctx, req.NamespacedName, &ps)
	return ps, err
}

func (r *Reconciler) handleFetchError(err error, log logr.Logger, ps *esapi.PushSecret) (ctrl.Result, error) {
	if apierrors.IsNotFound(err) {
		return ctrl.Result{}, nil
	}
	msg := "unable to get PushSecret"
	r.recorder.Event(ps, v1.EventTypeWarning, esapi.ReasonErrored, msg)
	log.Error(err, msg)
	return ctrl.Result{}, fmt.Errorf("get resource: %w", err)
}

func (r *Reconciler) initializeManager(ctx context.Context) secretstore.Manager {
	return secretstore.NewManager(r.Client, r.ControllerClass, false)
}

func (r *Reconciler) getRefreshInterval(ps esapi.PushSecret) time.Duration {
	if ps.Spec.RefreshInterval != nil {
		return ps.Spec.RefreshInterval.Duration
	}
	return r.RequeueInterval
}

func (r *Reconciler) manageFinalizers(ctx context.Context, ps *esapi.PushSecret, mgr secretstore.Manager, log logr.Logger) error {
	switch ps.Spec.DeletionPolicy {
	case esapi.PushSecretDeletionPolicyDelete:
		return r.handleFinalizerDeletion(ctx, ps, mgr, log)
	case esapi.PushSecretDeletionPolicyNone:
		return r.removeFinalizerIfPresent(ctx, ps, log)
	default:
		return nil
	}
}

func (r *Reconciler) handleFinalizerDeletion(ctx context.Context, ps *esapi.PushSecret, mgr secretstore.Manager, log logr.Logger) error {
	if ps.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.addFinalizerIfAbsent(ctx, ps, log)
	}
	return r.cleanupAndRemoveFinalizer(ctx, ps, mgr, log)
}

func (r *Reconciler) addFinalizerIfAbsent(ctx context.Context, ps *esapi.PushSecret, log logr.Logger) error {
	if !controllerutil.ContainsFinalizer(ps, pushSecretFinalizer) {
		controllerutil.AddFinalizer(ps, pushSecretFinalizer)
		if err := r.Client.Update(ctx, ps, &client.UpdateOptions{}); err != nil {
			return fmt.Errorf("could not update finalizers: %w", err)
		}
		return nil
	}
	return nil
}

func (r *Reconciler) handleSecretStoreError(err error, ps *esapi.PushSecret) (ctrl.Result, error) {
	r.markAsFailed(err.Error(), ps, nil)
	return ctrl.Result{}, err
}

func (r *Reconciler) handleSecretError(err error, ps *esapi.PushSecret) (ctrl.Result, error) {
	r.markAsFailed(errFailedGetSecret, ps, nil)
	return ctrl.Result{}, err
}

func (r *Reconciler) removeFinalizerIfPresent(ctx context.Context, ps *esapi.PushSecret, log logr.Logger) error {
	if controllerutil.ContainsFinalizer(ps, pushSecretFinalizer) {
		controllerutil.RemoveFinalizer(ps, pushSecretFinalizer)
		if err := r.Client.Update(ctx, ps, &client.UpdateOptions{}); err != nil {
			return fmt.Errorf("could not update finalizers: %w", err)
		}
	}
	return nil
}

func (r *Reconciler) cleanupAndRemoveFinalizer(ctx context.Context, ps *esapi.PushSecret, mgr secretstore.Manager, log logr.Logger) error {
	if controllerutil.ContainsFinalizer(ps, pushSecretFinalizer) {
		badState, err := r.DeleteSecretFromProviders(ctx, ps, esapi.SyncedPushSecretsMap{}, mgr)
		if err != nil {
			r.markAsFailed(fmt.Sprintf("Failed to Delete Secrets from Provider: %v", err), ps, badState)
			return err
		}
		controllerutil.RemoveFinalizer(ps, pushSecretFinalizer)
		if err := r.Client.Update(ctx, ps, &client.UpdateOptions{}); err != nil {
			return fmt.Errorf("could not update finalizers: %w", err)
		}
	}
	return nil
}

func (r *Reconciler) getManagedSecretStores(ctx context.Context, ps esapi.PushSecret, namespace string) ([]esapi.SecretStore, error) {
	secretStores, err := r.GetSecretStores(ctx, ps)
	if err != nil {
		return nil, err
	}
	return removeUnmanagedStores(ctx, namespace, r, secretStores)
}

func (r *Reconciler) pushSecretsToProviders(ctx context.Context, secretStores []esapi.SecretStore, ps esapi.PushSecret, secret corev1.Secret, mgr secretstore.Manager, log logr.Logger) (esapi.SyncedPushSecretsMap, error) {
	syncedSecrets, err := r.PushSecretToProviders(ctx, secretStores, ps, secret, mgr)
	if err != nil && errors.Is(err, locks.ErrConflict) {
		log.Info("retry to acquire lock to update the secret later", "error", err)
		return nil, ctrl.Result{Requeue: true}
	}
	return syncedSecrets, err
}

func (r *Reconciler) handlePushError(err error, ps *esapi.PushSecret, syncedSecrets esapi.SyncedPushSecretsMap, log logr.Logger) (ctrl.Result, error) {
	totalSecrets := mergeSecretState(syncedSecrets, ps.Status.SyncedPushSecrets)
	msg := fmt.Sprintf(errFailedSetSecret, err)
	r.markAsFailed(msg, ps, totalSecrets)
	return ctrl.Result{}, err
}

func (r *Reconciler) handleDeletionPolicy(ctx context.Context, ps esapi.PushSecret, syncedSecrets esapi.SyncedPushSecretsMap, mgr secretstore.Manager) error {
	if ps.Spec.DeletionPolicy == esapi.PushSecretDeletionPolicyDelete {
		badSyncState, err := r.DeleteSecretFromProviders(ctx, &ps, syncedSecrets, mgr)
		if err != nil {
			msg := fmt.Sprintf("Failed to Delete Secrets from Provider: %v", err)
			r.markAsFailed(msg, &ps, badSyncState)
			return err
		}
	}
	return nil
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("pushsecret", req.NamespacedName)
	resourceLabels := ctrlmetrics.RefineNonConditionMetricLabels(map[string]string{"name": req.Name, "namespace": req.Namespace})
	start := time.Now()
	defer totalReconcileDuration(resourceLabels, start)


	ps, err := r.fetchPushSecret(ctx, req)
	if err != nil {
		return r.handleFetchError(err, log, &ps)
	}

	mgr := r.initializeManager(ctx)
	defer mgr.Close(ctx)

	refreshInt := r.getRefreshInterval(ps)
	if err := r.manageFinalizers(ctx, &ps, mgr, log); err != nil {
		return ctrl.Result{}, err
	}

	secret, err := r.getSecret(ctx, ps)
	if err != nil {
		return r.handleSecretError(err, &ps)
	}

	secretStores, err := r.getManagedSecretStores(ctx, ps, req.Namespace)
	if err != nil {
		return r.handleSecretStoreError(err, &ps)
	}

	if err := r.applyTemplate(ctx, &ps, secret); err != nil {
		return ctrl.Result{}, err
	}

	syncedSecrets, err := r.pushSecretsToProviders(ctx, secretStores, ps, secret, mgr, log)
	if err != nil {
		return r.handlePushError(err, &ps, syncedSecrets, log)
	}

	if err := r.handleDeletionPolicy(ctx, ps, syncedSecrets, mgr); err != nil {
		return ctrl.Result{}, err
	}

	r.markAsDone(&ps, syncedSecrets)
	return ctrl.Result{RequeueAfter: refreshInt}, nil
}

func (r *Reconciler) markAsFailed(msg string, ps *esapi.PushSecret, syncState esapi.SyncedPushSecretsMap) {
	cond := newPushSecretCondition(esapi.PushSecretReady, v1.ConditionFalse, esapi.ReasonErrored, msg)
	setPushSecretCondition(ps, *cond)
	if syncState != nil {
		r.setSecrets(ps, syncState)
	}
	r.recorder.Event(ps, v1.EventTypeWarning, esapi.ReasonErrored, msg)
}

func (r *Reconciler) markAsDone(ps *esapi.PushSecret, secrets esapi.SyncedPushSecretsMap) {
	msg := "PushSecret synced successfully"
	if ps.Spec.UpdatePolicy == esapi.PushSecretUpdatePolicyIfNotExists {
		msg += ". Existing secrets in providers unchanged."
	}
	cond := newPushSecretCondition(esapi.PushSecretReady, v1.ConditionTrue, esapi.ReasonSynced, msg)
	setPushSecretCondition(ps, *cond)
	r.setSecrets(ps, secrets)
	r.recorder.Event(ps, v1.EventTypeNormal, esapi.ReasonSynced, msg)
}

func (r *Reconciler) setSecrets(ps *esapi.PushSecret, status esapi.SyncedPushSecretsMap) {
	ps.Status.SyncedPushSecrets = status
}

func mergeSecretState(newMap, old esapi.SyncedPushSecretsMap) esapi.SyncedPushSecretsMap {
	out := newMap.DeepCopy()
	for k, v := range old {
		_, ok := out[k]
		if !ok {
			out[k] = make(map[string]esapi.PushSecretData)
		}
		maps.Insert(out[k], maps.All(v))
	}
	return out
}

func (r *Reconciler) DeleteSecretFromProviders(ctx context.Context, ps *esapi.PushSecret, newMap esapi.SyncedPushSecretsMap, mgr *secretstore.Manager) (esapi.SyncedPushSecretsMap, error) {
	out := mergeSecretState(newMap, ps.Status.SyncedPushSecrets)
	for storeName, oldData := range ps.Status.SyncedPushSecrets {
		storeRef := v1beta1.SecretStoreRef{
			Name: strings.Split(storeName, "/")[1],
			Kind: strings.Split(storeName, "/")[0],
		}
		client, err := mgr.Get(ctx, storeRef, ps.Namespace, nil)
		if err != nil {
			return out, fmt.Errorf("could not get secrets client for store %v: %w", storeName, err)
		}
		newData, ok := newMap[storeName]
		if !ok {
			err = r.DeleteAllSecretsFromStore(ctx, client, oldData)
			if err != nil {
				return out, err
			}
			delete(out, storeName)
			continue
		}
		for oldEntry, oldRef := range oldData {
			_, ok := newData[oldEntry]
			if !ok {
				err = r.DeleteSecretFromStore(ctx, client, oldRef)
				if err != nil {
					return out, err
				}
				delete(out[storeName], oldRef.Match.RemoteRef.RemoteKey)
			}
		}
	}
	return out, nil
}

func (r *Reconciler) DeleteAllSecretsFromStore(ctx context.Context, client v1beta1.SecretsClient, data map[string]esapi.PushSecretData) error {
	for _, v := range data {
		err := r.DeleteSecretFromStore(ctx, client, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) DeleteSecretFromStore(ctx context.Context, client v1beta1.SecretsClient, data esapi.PushSecretData) error {
	return client.DeleteSecret(ctx, data.Match.RemoteRef)
}

func (r *Reconciler) PushSecretToProviders(ctx context.Context, stores map[esapi.PushSecretStoreRef]v1beta1.GenericStore, ps esapi.PushSecret, secret *v1.Secret, mgr *secretstore.Manager) (esapi.SyncedPushSecretsMap, error) {
	out := make(esapi.SyncedPushSecretsMap)
	for ref, store := range stores {
		out, err := r.handlePushSecretDataForStore(ctx, ps, secret, out, mgr, store.GetName(), ref.Kind)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func (r *Reconciler) handlePushSecretDataForStore(ctx context.Context, ps esapi.PushSecret, secret *v1.Secret, out esapi.SyncedPushSecretsMap, mgr *secretstore.Manager, storeName, refKind string) (esapi.SyncedPushSecretsMap, error) {
	storeKey := fmt.Sprintf("%v/%v", refKind, storeName)
	out[storeKey] = make(map[string]esapi.PushSecretData)
	storeRef := v1beta1.SecretStoreRef{
		Name: storeName,
		Kind: refKind,
	}
	originalSecretData := secret.Data
	secretClient, err := mgr.Get(ctx, storeRef, ps.GetNamespace(), nil)
	if err != nil {
		return out, fmt.Errorf("could not get secrets client for store %v: %w", storeName, err)
	}
	for _, data := range ps.Spec.Data {
		secretData, err := utils.ReverseKeys(data.ConversionStrategy, originalSecretData)
		if err != nil {
			return nil, fmt.Errorf(errConvert, err)
		}
		secret.Data = secretData
		key := data.GetSecretKey()
		if !secretKeyExists(key, secret) {
			return out, fmt.Errorf("secret key %v does not exist", key)
		}
		switch ps.Spec.UpdatePolicy {
		case esapi.PushSecretUpdatePolicyIfNotExists:
			exists, err := secretClient.SecretExists(ctx, data.Match.RemoteRef)
			if err != nil {
				return out, fmt.Errorf("could not verify if secret exists in store: %w", err)
			} else if exists {
				out[storeKey][statusRef(data)] = data
				continue
			}
		case esapi.PushSecretUpdatePolicyReplace:
		default:
		}
		if err := secretClient.PushSecret(ctx, secret, data); err != nil {
			return out, fmt.Errorf(errSetSecretFailed, key, storeName, err)
		}
		out[storeKey][statusRef(data)] = data
	}
	return out, nil
}

func secretKeyExists(key string, secret *v1.Secret) bool {
	_, ok := secret.Data[key]
	return key == "" || ok
}

func (r *Reconciler) GetSecret(ctx context.Context, ps esapi.PushSecret) (*v1.Secret, error) {
	secretName := types.NamespacedName{Name: ps.Spec.Selector.Secret.Name, Namespace: ps.Namespace}
	secret := &v1.Secret{}
	err := r.Client.Get(ctx, secretName, secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (r *Reconciler) GetSecretStores(ctx context.Context, ps esapi.PushSecret) (map[esapi.PushSecretStoreRef]v1beta1.GenericStore, error) {
	stores := make(map[esapi.PushSecretStoreRef]v1beta1.GenericStore)
	for _, refStore := range ps.Spec.SecretStoreRefs {
		if refStore.LabelSelector != nil {
			labelSelector, err := metav1.LabelSelectorAsSelector(refStore.LabelSelector)
			if err != nil {
				return nil, fmt.Errorf("could not convert labels: %w", err)
			}
			if refStore.Kind == v1beta1.ClusterSecretStoreKind {
				clusterSecretStoreList := v1beta1.ClusterSecretStoreList{}
				err = r.List(ctx, &clusterSecretStoreList, &client.ListOptions{LabelSelector: labelSelector})
				if err != nil {
					return nil, fmt.Errorf("could not list cluster Secret Stores: %w", err)
				}
				for k, v := range clusterSecretStoreList.Items {
					key := esapi.PushSecretStoreRef{
						Name: v.Name,
						Kind: v1beta1.ClusterSecretStoreKind,
					}
					stores[key] = &clusterSecretStoreList.Items[k]
				}
			} else {
				secretStoreList := v1beta1.SecretStoreList{}
				err = r.List(ctx, &secretStoreList, &client.ListOptions{LabelSelector: labelSelector})
				if err != nil {
					return nil, fmt.Errorf("could not list Secret Stores: %w", err)
				}
				for k, v := range secretStoreList.Items {
					key := esapi.PushSecretStoreRef{
						Name: v.Name,
						Kind: v1beta1.SecretStoreKind,
					}
					stores[key] = &secretStoreList.Items[k]
				}
			}
		} else {
			store, err := r.getSecretStoreFromName(ctx, refStore, ps.Namespace)
			if err != nil {
				return nil, err
			}
			stores[refStore] = store
		}
	}
	return stores, nil
}

func (r *Reconciler) getSecretStoreFromName(ctx context.Context, refStore esapi.PushSecretStoreRef, ns string) (v1beta1.GenericStore, error) {
	if refStore.Name == "" {
		return nil, errors.New("refStore Name must be provided")
	}
	ref := types.NamespacedName{
		Name: refStore.Name,
	}
	if refStore.Kind == v1beta1.ClusterSecretStoreKind {
		var store v1beta1.ClusterSecretStore
		err := r.Get(ctx, ref, &store)
		if err != nil {
			return nil, fmt.Errorf(errGetClusterSecretStore, ref.Name, err)
		}
		return &store, nil
	}
	ref.Namespace = ns
	var store v1beta1.SecretStore
	err := r.Get(ctx, ref, &store)
	if err != nil {
		return nil, fmt.Errorf(errGetSecretStore, ref.Name, err)
	}
	return &store, nil
}

func newPushSecretCondition(condType esapi.PushSecretConditionType, status v1.ConditionStatus, reason, message string) *esapi.PushSecretStatusCondition {
	return &esapi.PushSecretStatusCondition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
}

func setPushSecretCondition(ps *esapi.PushSecret, condition esapi.PushSecretStatusCondition) {
	currentCond := getPushSecretCondition(ps.Status, condition.Type)
	if currentCond != nil && currentCond.Status == condition.Status &&
		currentCond.Reason == condition.Reason && currentCond.Message == condition.Message {
		return
	}

	// Do not update lastTransitionTime if the status of the condition doesn't change.
	if currentCond != nil && currentCond.Status == condition.Status {
		condition.LastTransitionTime = currentCond.LastTransitionTime
	}

	ps.Status.Conditions = append(filterOutCondition(ps.Status.Conditions, condition.Type), condition)
}

// filterOutCondition returns an empty set of conditions with the provided type.
func filterOutCondition(conditions []esapi.PushSecretStatusCondition, condType esapi.PushSecretConditionType) []esapi.PushSecretStatusCondition {
	newConditions := make([]esapi.PushSecretStatusCondition, 0, len(conditions))
	for _, c := range conditions {
		if c.Type == condType {
			continue
		}
		newConditions = append(newConditions, c)
	}
	return newConditions
}

// getPushSecretCondition returns the condition with the provided type.
func getPushSecretCondition(status esapi.PushSecretStatus, condType esapi.PushSecretConditionType) *esapi.PushSecretStatusCondition {
	for i := range status.Conditions {
		c := status.Conditions[i]
		if c.Type == condType {
			return &c
		}
	}
	return nil
}

func statusRef(ref v1beta1.PushSecretData) string {
	if ref.GetProperty() != "" {
		return ref.GetRemoteKey() + "/" + ref.GetProperty()
	}
	return ref.GetRemoteKey()
}

// removeUnmanagedStores iterates over all SecretStore references and evaluates the controllerClass property.
// Returns a map containing only managed stores.
func removeUnmanagedStores(ctx context.Context, namespace string, r *Reconciler, ss map[esapi.PushSecretStoreRef]v1beta1.GenericStore) (map[esapi.PushSecretStoreRef]v1beta1.GenericStore, error) {
	for ref := range ss {
		var store v1beta1.GenericStore
		switch ref.Kind {
		case v1beta1.SecretStoreKind:
			store = &v1beta1.SecretStore{}
		case v1beta1.ClusterSecretStoreKind:
			store = &v1beta1.ClusterSecretStore{}
			namespace = ""
		}
		err := r.Client.Get(ctx, types.NamespacedName{
			Name:      ref.Name,
			Namespace: namespace,
		}, store)

		if err != nil {
			return ss, err
		}

		class := store.GetSpec().Controller
		if class != "" && class != r.ControllerClass {
			delete(ss, ref)
		}
	}
	return ss, nil
}
