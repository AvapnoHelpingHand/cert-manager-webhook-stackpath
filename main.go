package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"

	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	"golang.org/x/oauth2"

	spdns "github.com/avapnohelpinghand/cert-manager-webhook-stackpath/pkg/dns"
	spauth "github.com/avapnohelpinghand/cert-manager-webhook-stackpath/pkg/oauth2"
)

// SPDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type SPDNSProviderSolver struct {
	client *kubernetes.Clientset
	ctx    context.Context
}

// SPDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type SPDNSProviderConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	Stack        cmmetav1.SecretKeySelector `json:"Stack"`
	ClientID     cmmetav1.SecretKeySelector `json:"ClientID"`
	ClientSecret cmmetav1.SecretKeySelector `json:"ClientSecret"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *SPDNSProviderSolver) Name() string {
	return "stackpath"
}

func (c *SPDNSProviderSolver) getSecretData(selector cmmetav1.SecretKeySelector, ns string) (string, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(c.ctx, selector.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to load secret %s/%s: %w", ns, selector.Name, err)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return string(data), nil
	}

	return "", fmt.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}

func (c *SPDNSProviderSolver) newClientFromConfig(ch *v1alpha1.ChallengeRequest) (*spdns.APIClient, string, context.Context, error) {
	cfg, err := c.loadConfig(ch)
	if err != nil {
		return nil, "", nil, err
	}

	stack, err := c.getSecretData(cfg.Stack, ch.ResourceNamespace)
	if err != nil {
		return nil, "", nil, err
	}

	clientid, err := c.getSecretData(cfg.ClientID, ch.ResourceNamespace)
	if err != nil {
		return nil, "", nil, err
	}

	clientsecret, err := c.getSecretData(cfg.ClientSecret, ch.ResourceNamespace)
	if err != nil {
		return nil, "", nil, err
	}

	var ts oauth2.TokenSource = spauth.NewTokenSource(clientid, clientsecret)
	auth := context.WithValue(c.ctx, spdns.ContextOAuth2, ts)

	return spdns.NewAPIClient(spdns.NewConfiguration()), stack, auth, nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *SPDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	stackpath, stack, auth, err := c.newClientFromConfig(ch)
	request := stackpath.ResourceRecordsApi.CreateZoneRecord(auth, stack, ch.ResolvedZone)
	var ttl int32 = 600
	var weight int32 = 10
	request = request.ZoneUpdateZoneRecordMessage(
		spdns.ZoneUpdateZoneRecordMessage{
			Name:   &ch.ResolvedFQDN,
			Type:   spdns.ZONERECORDTYPE_TXT.Ptr(),
			Ttl:    &ttl,
			Data:   &ch.Key,
			Weight: &weight,
		},
	)
	_, r, err := request.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ResourceRecordsApi.CreateZoneRecord``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}

	// TODO: add code that sets a record in the DNS provider's console
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *SPDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// TODO: add code that deletes a record from the DNS provider's console

	stackpath, stack, auth, err := c.newClientFromConfig(ch)
	if err != nil {
		return err
	}

	resp, err := stackpath.ResourceRecordsApi.DeleteZoneRecord(auth, stack, ch.ResolvedZone, ch.Key).Execute()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ResourceRecordsApi.DeleteZoneRecord``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", resp)
		return err
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *SPDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func (c *SPDNSProviderSolver) loadConfig(ch *v1alpha1.ChallengeRequest) (SPDNSProviderConfig, error) {
	cfg := SPDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if ch.Config == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(ch.Config.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func main() {
	ctx := context.Background()

	groupName := os.Getenv("GROUP_NAME")
	if groupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(groupName,
		&SPDNSProviderSolver{ctx: ctx},
	)
}
