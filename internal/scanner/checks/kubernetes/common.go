// Package kubernetes contains CNAPP security checks for Kubernetes clusters
// based on Prowler's Kubernetes provider (v5.41).
package kubernetes

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// unstructuredNestedBool safely retrieves a bool from an unstructured map.
func unstructuredNestedBool(obj map[string]interface{}, fields ...string) (bool, bool, error) {
	v, found, err := unstructured.NestedBool(obj, fields...)
	return v, found, err
}

// unstructuredNestedStringSlice safely retrieves a string slice from an unstructured map.
func unstructuredNestedStringSlice(obj map[string]interface{}, fields ...string) ([]string, bool, error) {
	v, found, err := unstructured.NestedStringSlice(obj, fields...)
	return v, found, err
}

// unstructuredNestedMap safely retrieves a map from an unstructured object.
func unstructuredNestedMap(obj map[string]interface{}, fields ...string) (map[string]interface{}, bool, error) {
	v, found, err := unstructured.NestedMap(obj, fields...)
	return v, found, err
}

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool { return &b }

// KubernetesProviderClient is the interface that every check expects from the
// provider when Execute is called. It mirrors the methods available on Provider.
type KubernetesProviderClient interface {
	ListNodes(ctx context.Context) (*corev1.NodeList, error)
	ListPods(ctx context.Context, namespace string) (*corev1.PodList, error)
	ListNamespaces(ctx context.Context) (*corev1.NamespaceList, error)
	ListClusterRoles(ctx context.Context) (*rbacv1.ClusterRoleList, error)
	ListClusterRoleBindings(ctx context.Context) (*rbacv1.ClusterRoleBindingList, error)
	ListRoles(ctx context.Context, namespace string) (*rbacv1.RoleList, error)
	ListRoleBindings(ctx context.Context, namespace string) (*rbacv1.RoleBindingList, error)
	ListServiceAccounts(ctx context.Context, namespace string) (*corev1.ServiceAccountList, error)
	ListConfigMaps(ctx context.Context, namespace string) (*corev1.ConfigMapList, error)
	ListSecrets(ctx context.Context, namespace string) (*corev1.SecretList, error)
	ListDaemonSets(ctx context.Context, namespace string) (*appsv1.DaemonSetList, error)
	ListDeployments(ctx context.Context, namespace string) (*appsv1.DeploymentList, error)
	ListStatefulSets(ctx context.Context, namespace string) (*appsv1.StatefulSetList, error)
	ListReplicaSets(ctx context.Context, namespace string) (*appsv1.ReplicaSetList, error)
	ListCronJobs(ctx context.Context, namespace string) (*batchv1.CronJobList, error)
	ListJobs(ctx context.Context, namespace string) (*batchv1.JobList, error)
	ListNetworkPolicies(ctx context.Context, namespace string) (*networkingv1.NetworkPolicyList, error)
	ListPodSecurityPolicies(ctx context.Context) (interface{}, error)
	ListResourceQuotas(ctx context.Context, namespace string) (*corev1.ResourceQuotaList, error)
	ListLimitRanges(ctx context.Context, namespace string) (*corev1.LimitRangeList, error)
	ListHorizontalPodAutoscalers(ctx context.Context, namespace string) (*autoscalingv2.HorizontalPodAutoscalerList, error)
	ListIngresses(ctx context.Context, namespace string) (*networkingv1.IngressList, error)
	ListStorageClasses(ctx context.Context) (*storagev1.StorageClassList, error)
	ListPersistentVolumes(ctx context.Context) (*corev1.PersistentVolumeList, error)
	ListPersistentVolumeClaims(ctx context.Context, namespace string) (*corev1.PersistentVolumeClaimList, error)
}

// ---- Shared helpers -------------------------------------------------------

// podContainers returns all containers (including init containers) from a pod.
func podContainers(p corev1.Pod) []corev1.Container {
	containers := append([]corev1.Container{}, p.Spec.Containers...)
	containers = append(containers, p.Spec.InitContainers...)
	return containers
}

// allPodImages returns the list of image strings used by a pod.
func allPodImages(p corev1.Pod) []string {
	var imgs []string
	for _, c := range podContainers(p) {
		imgs = append(imgs, c.Image)
	}
	return imgs
}

// isLatestTag returns true when the image reference has no explicit tag or
// explicitly uses :latest.
func isLatestTag(image string) bool {
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		return image[idx+1:] == "latest"
	}
	// No tag means :latest by convention in Docker/K8s.
	return true
}

// hasLiveness returns true when the container has a liveness probe.
func hasLiveness(c corev1.Container) bool { return c.LivenessProbe != nil }

// hasReadiness returns true when the container has a readiness probe.
func hasReadiness(c corev1.Container) bool { return c.ReadinessProbe != nil }

// hasCPULimit reports whether the container has a non-zero CPU limit set.
func hasCPULimit(c corev1.Container) bool {
	return c.Resources.Limits.Cpu() != nil && !c.Resources.Limits.Cpu().IsZero()
}

// hasMemoryLimit reports whether the container has a non-zero memory limit.
func hasMemoryLimit(c corev1.Container) bool {
	return c.Resources.Limits.Memory() != nil && !c.Resources.Limits.Memory().IsZero()
}

// hasCPURequest reports whether the container has a non-zero CPU request.
func hasCPURequest(c corev1.Container) bool {
	return c.Resources.Requests.Cpu() != nil && !c.Resources.Requests.Cpu().IsZero()
}

// hasMemoryRequest reports whether the container has a non-zero memory request.
func hasMemoryRequest(c corev1.Container) bool {
	return c.Resources.Requests.Memory() != nil && !c.Resources.Requests.Memory().IsZero()
}

// allowsPrivilegeEscalation returns true if allowPrivilegeEscalation is not
// explicitly set to false (the secure default is false).
func allowsPrivilegeEscalation(c corev1.Container) bool {
	if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil {
		return true // unset means allowed (default)
	}
	return *c.SecurityContext.AllowPrivilegeEscalation
}

// runsAsRoot returns true when runAsNonRoot is not explicitly set to true.
func runsAsRoot(pod corev1.Pod, c corev1.Container) bool {
	if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
		return !*c.SecurityContext.RunAsNonRoot
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil {
		return !*pod.Spec.SecurityContext.RunAsNonRoot
	}
	return true
}

// isPrivileged returns true when a container runs in privileged mode.
func isPrivileged(c corev1.Container) bool {
	return c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged
}

// hasReadOnlyRootFilesystem returns true when read-only root FS is set.
func hasReadOnlyRootFilesystem(c corev1.Container) bool {
	return c.SecurityContext != nil && c.SecurityContext.ReadOnlyRootFilesystem != nil &&
		*c.SecurityContext.ReadOnlyRootFilesystem
}

// hasSeccompProfile returns true when a seccomp profile is set (either
// pod-level or container-level).
func hasSeccompProfile(pod corev1.Pod, c corev1.Container) bool {
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil &&
		c.SecurityContext.SeccompProfile.Type != "" {
		return true
	}
	return pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil &&
		pod.Spec.SecurityContext.SeccompProfile.Type != ""
}

// isRuntimeDefaultSeccomp returns true when the effective seccomp profile is
// RuntimeDefault.
func isRuntimeDefaultSeccomp(pod corev1.Pod, c corev1.Container) bool {
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil &&
		c.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault {
		return true
	}
	return pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil &&
		pod.Spec.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault
}

// hasSecurityContext returns true when any security context is set.
func hasSecurityContext(c corev1.Container) bool {
	return c.SecurityContext != nil
}

// usesHostPort returns true when any container port binds to hostPort.
func usesHostPort(pod corev1.Pod) bool {
	for _, c := range podContainers(pod) {
		for _, port := range c.Ports {
			if port.HostPort > 0 {
				return true
			}
		}
	}
	return false
}

// usesHostPath returns true when the pod mounts a hostPath volume.
func usesHostPath(pod corev1.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			return true
		}
	}
	return false
}

// usesHostNamespace reports whether the pod uses hostNetwork, hostPID, or
// hostIPC.
func usesHostNetwork(pod corev1.Pod) bool  { return pod.Spec.HostNetwork }
func usesHostPID(pod corev1.Pod) bool      { return pod.Spec.HostPID }
func usesHostIPC(pod corev1.Pod) bool      { return pod.Spec.HostIPC }

// hasAddedCapabilities reports whether a container adds Linux capabilities.
func hasAddedCapabilities(c corev1.Container) bool {
	return c.SecurityContext != nil && c.SecurityContext.Capabilities != nil &&
		len(c.SecurityContext.Capabilities.Add) > 0
}

// hasDroppedAllCapabilities returns true when ALL capabilities are dropped.
func hasDroppedAllCapabilities(c corev1.Container) bool {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return false
	}
	for _, d := range c.SecurityContext.Capabilities.Drop {
		return string(d) == "ALL"
	}
	return false
}

// hasCapabilitiesAssigned reports whether any capabilities are assigned (add).
func hasCapabilitiesAssigned(c corev1.Container) bool {
	return hasAddedCapabilities(c)
}

// hasNETRawCapability returns true when NET_RAW is in the added capabilities.
func hasNETRawCapability(c corev1.Container) bool {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return false
	}
	for _, cap := range c.SecurityContext.Capabilities.Add {
		if string(cap) == "NET_RAW" {
			return true
		}
	}
	return false
}

// usesHostProcess is a Windows-specific check. Since Go can't easily detect
// Windows node features, we check for windows-specific security context fields.
func usesHostProcess(_ corev1.Pod) bool {
	// On Linux-only clusters this is always false. Implemented as no-op since
	// we cannot detect Windows hostProcess via typed API on Linux clients.
	return false
}

// hasSecretInEnv returns true when any env var references a secretKeyRef or
// secretRef.
func hasSecretInEnv(c corev1.Container) bool {
	for _, env := range c.Env {
		if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
			return true
		}
	}
	for _, envFrom := range c.EnvFrom {
		if envFrom.SecretRef != nil {
			return true
		}
	}
	return false
}

// wildcardSubjects returns subjects in rules/resources that use wildcard verbs
// or resources.
func hasWildcardVerbsOrResources(rules []rbacv1.PolicyRule) bool {
	for _, r := range rules {
		for _, v := range r.Verbs {
			if v == "*" {
				return true
			}
		}
		for _, res := range r.Resources {
			if res == "*" {
				return true
			}
		}
	}
	return false
}

// hasDangerousSecretAccess checks if a role has secrets GET/LIST/WATCH.
func hasDangerousSecretAccess(rules []rbacv1.PolicyRule) bool {
	dangerousVerbs := map[string]bool{"get": true, "list": true, "watch": true}
	for _, r := range rules {
		for _, res := range r.Resources {
			if res == "secrets" || res == "*" {
				for _, v := range r.Verbs {
					if dangerousVerbs[strings.ToLower(v)] || v == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasPodCreateAccess checks if a role has pod CREATE permission.
func hasPodCreateAccess(rules []rbacv1.PolicyRule) bool {
	for _, r := range rules {
		for _, res := range r.Resources {
			if res == "pods" || res == "*" {
				for _, v := range r.Verbs {
					if strings.ToLower(v) == "create" || v == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasPVCreateAccess checks if a role has persistentvolumes CREATE.
func hasPVCreateAccess(rules []rbacv1.PolicyRule) bool {
	for _, r := range rules {
		for _, res := range r.Resources {
			if res == "persistentvolumes" || res == "*" {
				for _, v := range r.Verbs {
					if strings.ToLower(v) == "create" || v == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasCSRApprovalAccess checks if a role has certificatesigningrequests/approve.
func hasCSRApprovalAccess(rules []rbacv1.PolicyRule) bool {
	for _, r := range rules {
		for _, res := range r.Resources {
			if res == "certificatesigningrequests/approve" || res == "*" {
				for _, v := range r.Verbs {
					if strings.ToLower(v) == "update" || strings.ToLower(v) == "create" || v == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasNodeProxyAccess checks if a role has nodes/proxy subresource.
func hasNodeProxyAccess(rules []rbacv1.PolicyRule) bool {
	for _, r := range rules {
		for _, res := range r.Resources {
			if strings.HasPrefix(res, "nodes/") || res == "*" {
				for _, v := range r.Verbs {
					if strings.ToLower(v) == "get" || strings.ToLower(v) == "create" || v == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasTokenCreateAccess checks if a role has serviceaccounts/token CREATE.
func hasTokenCreateAccess(rules []rbacv1.PolicyRule) bool {
	for _, r := range rules {
		for _, res := range r.Resources {
			if res == "serviceaccounts/token" || res == "*" {
				for _, v := range r.Verbs {
					if strings.ToLower(v) == "create" || v == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasWebhookConfigAccess checks if a role has mutating/validating webhook config.
func hasWebhookConfigAccess(rules []rbacv1.PolicyRule) bool {
	sensitive := map[string]bool{
		"mutatingwebhookconfigurations":   true,
		"validatingwebhookconfigurations": true,
	}
	for _, r := range rules {
		for _, res := range r.Resources {
			if sensitive[res] || res == "*" {
				for _, v := range r.Verbs {
					if v == "*" || strings.ToLower(v) == "update" || strings.ToLower(v) == "create" {
						return true
					}
				}
			}
		}
	}
	return false
}

// podSecurityLevel returns the PodSecurityLevel string from annotations.
// Returns empty string when not set.
func podSecurityLevel(pod corev1.Pod) string {
	if pod.Annotations == nil {
		return ""
	}
	if lvl, ok := pod.Annotations["kubernetes.io/psp"]; ok {
		return lvl
	}
	if lvl, ok := pod.Annotations["seccomp.security.alpha.kubernetes.io/pod"]; ok {
		return lvl
	}
	return ""
}

// safeDeref returns "" for nil pointer, otherwise dereferences.
func safeDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// formatSubject formats a RBAC subject for display.
func formatSubject(s rbacv1.Subject) string {
	return fmt.Sprintf("%s/%s (%s)", s.Namespace, s.Name, s.Kind)
}
