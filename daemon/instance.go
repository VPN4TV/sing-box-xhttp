package daemon

import (
	"bytes"
	"context"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/experimental/locale"
	"github.com/sagernet/sing-box/experimental/vpn4tvbridge"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type Instance struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	instance              *box.Box
	connectionManager     adapter.ConnectionManager
	clashServer           adapter.ClashServer
	trafficManager        *trafficcontrol.Manager
	cacheFile             adapter.CacheFile
	pauseManager          pause.Manager
	urlTestHistoryStorage *urltest.HistoryStorage
	outboundManager       adapter.OutboundManager
	endpointManager       adapter.EndpointManager
	logFactory            log.Factory
	// VPN4TV: bridge configs carried by the profile, started with the instance.
	bridgeConfig *vpn4tvbridge.Config
}

func (s *StartedService) CheckConfig(ctx context.Context, configContent string) error {
	selectedLocale := locale.FromContext(ctx)
	ctx, _ = locale.ContextWithLocale(s.ctx, selectedLocale.Locale)
	// VPN4TV: the profile may carry the embedded bridge configs under a private
	// key. newInstance already strips it before parsing; this path did not, so
	// importing any profile with a bridge failed with `unknown field "vpn4tv"`.
	configContent, _, err := vpn4tvbridge.Extract(configContent)
	if err != nil {
		return err
	}
	options, err := parseConfig(ctx, configContent)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err == nil {
		instance.Close()
	}
	return err
}

func (s *StartedService) FormatConfig(ctx context.Context, configContent string) (string, error) {
	selectedLocale := locale.FromContext(ctx)
	ctx, _ = locale.ContextWithLocale(s.ctx, selectedLocale.Locale)
	// VPN4TV: same as CheckConfig, but the bridge configs have to go back in —
	// formatting a profile must not quietly drop them.
	configContent, bridgeConfig, err := vpn4tvbridge.Extract(configContent)
	if err != nil {
		return "", err
	}
	options, err := parseConfig(ctx, configContent)
	if err != nil {
		return "", err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(options)
	if err != nil {
		return "", err
	}
	return vpn4tvbridge.Attach(buffer.String(), bridgeConfig)
}

type OverrideOptions struct {
	AutoRedirect   bool
	IncludePackage []string
	ExcludePackage []string
}

func (s *StartedService) newInstance(ctx context.Context, profileContent string, overrideOptions *OverrideOptions) (*Instance, error) {
	selectedLocale := locale.FromContext(ctx)
	ctx, _ = locale.ContextWithLocale(s.ctx, selectedLocale.Locale)
	ctx = service.ExtendContext(ctx)
	service.MustRegister[deprecated.Manager](ctx, new(deprecatedManager))
	ctx, cancel := context.WithCancel(ctx)
	// VPN4TV: the profile may carry the embedded bridge configs (xray/outline/
	// wireproxy) under a private key. Pull them out before parsing — sing-box
	// rejects unknown fields — and start them below, once the config is valid.
	profileContent, bridgeConfig, err := vpn4tvbridge.Extract(profileContent)
	if err != nil {
		cancel()
		return nil, err
	}
	options, err := parseConfig(ctx, profileContent)
	if err != nil {
		cancel()
		return nil, err
	}
	if overrideOptions != nil {
		for _, inbound := range options.Inbounds {
			if tunInboundOptions, isTUN := inbound.Options.(*option.TunInboundOptions); isTUN {
				tunInboundOptions.AutoRedirect = overrideOptions.AutoRedirect
				tunInboundOptions.IncludePackage = append(tunInboundOptions.IncludePackage, overrideOptions.IncludePackage...)
				tunInboundOptions.ExcludePackage = append(tunInboundOptions.ExcludePackage, overrideOptions.ExcludePackage...)
				break
			}
		}
	}
	if s.oomKillerEnabled {
		if !common.Any(options.Services, func(it option.Service) bool {
			return it.Type == C.TypeOOMKiller
		}) {
			oomOptions := &option.OOMKillerServiceOptions{
				KillerDisabled:      s.oomKillerDisabled,
				MemoryLimitOverride: s.oomMemoryLimit,
			}
			options.Services = append(options.Services, option.Service{
				Type:    C.TypeOOMKiller,
				Options: oomOptions,
			})
		}
	}
	urlTestHistoryStorage := urltest.NewHistoryStorage()
	ctx = service.ContextWithPtr(ctx, urlTestHistoryStorage)
	i := &Instance{
		ctx:                   ctx,
		cancel:                cancel,
		urlTestHistoryStorage: urlTestHistoryStorage,
		bridgeConfig:          bridgeConfig,
	}
	boxInstance, err := box.New(box.Options{
		Context:           ctx,
		Options:           options,
		PlatformLogWriter: s,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	i.instance = boxInstance
	i.connectionManager = service.FromContext[adapter.ConnectionManager](ctx)
	i.clashServer = service.FromContext[adapter.ClashServer](ctx)
	i.trafficManager = service.PtrFromContext[trafficcontrol.Manager](ctx)
	i.pauseManager = service.FromContext[pause.Manager](ctx)
	i.cacheFile = service.FromContext[adapter.CacheFile](ctx)
	i.outboundManager = service.FromContext[adapter.OutboundManager](ctx)
	i.endpointManager = service.FromContext[adapter.EndpointManager](ctx)
	i.logFactory = boxInstance.LogFactory()
	log.SetStdLogger(boxInstance.LogFactory().Logger())
	return i, nil
}

func attachInstance(ctx context.Context) *Instance {
	return &Instance{
		ctx:                   ctx,
		connectionManager:     service.FromContext[adapter.ConnectionManager](ctx),
		clashServer:           service.FromContext[adapter.ClashServer](ctx),
		trafficManager:        service.PtrFromContext[trafficcontrol.Manager](ctx),
		pauseManager:          service.FromContext[pause.Manager](ctx),
		cacheFile:             service.FromContext[adapter.CacheFile](ctx),
		urlTestHistoryStorage: service.PtrFromContext[urltest.HistoryStorage](ctx),
		outboundManager:       service.FromContext[adapter.OutboundManager](ctx),
		endpointManager:       service.FromContext[adapter.EndpointManager](ctx),
		logFactory:            service.FromContext[log.Factory](ctx),
	}
}

func (i *Instance) Start() error {
	// VPN4TV: the daemon has no VpnService.protect; sing-tun's auto_route sends
	// every unbound socket of this process into the TUN, so a bridge dialling
	// its server would loop through the tunnel it feeds. Hand the bridges the
	// same interface binder sing-box's own dialers use.
	if networkManager := service.FromContext[adapter.NetworkManager](i.ctx); networkManager != nil {
		vpn4tvbridge.ProtectHook = networkManager.AutoDetectInterfaceFunc()
	}
	// Bridges must listen before sing-box dials its socks outbounds.
	if err := vpn4tvbridge.Start(i.bridgeConfig); err != nil {
		return err
	}
	err := i.instance.Start()
	if err != nil {
		vpn4tvbridge.Stop()
		return err
	}
	// olcrtc dials out the moment it starts; the binder above can only answer
	// once the box's interface monitor is running, hence after Start.
	if err := vpn4tvbridge.StartLate(i.bridgeConfig); err != nil {
		vpn4tvbridge.Stop()
		_ = i.instance.Close()
		return err
	}
	return nil
}

func (i *Instance) Close() error {
	i.cancel()
	vpn4tvbridge.Stop()
	i.urlTestHistoryStorage.Close()
	return i.instance.Close()
}

func (i *Instance) Box() *box.Box {
	return i.instance
}

func (i *Instance) PauseManager() pause.Manager {
	return i.pauseManager
}

func (i *Instance) TrafficManager() *trafficcontrol.Manager {
	return i.trafficManager
}

func parseConfig(ctx context.Context, configContent string) (option.Options, error) {
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(configContent))
	if err != nil {
		return option.Options{}, E.Cause(err, "decode config")
	}
	return options, nil
}
