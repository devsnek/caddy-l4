package l4caddyfile

import (
	"encoding/json"
	"strconv"
	"reflect"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4echo"
	"github.com/mholt/caddy-l4/modules/l4proxy"
	"github.com/mholt/caddy-l4/modules/l4proxyprotocol"
	"github.com/mholt/caddy-l4/modules/l4tls"
)

func init() {
	caddyconfig.RegisterAdapter("l4", caddyfile.Adapter{ServerType: ServerType{}})
}

type ServerType struct {}

func (st ServerType) Setup(
	inputServerBlocks []caddyfile.ServerBlock,
	options map[string]any,
) (*caddy.Config, []caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning

	l4app := &layer4.App{Servers: make(map[string]*layer4.Server)}

	tlsApp := &caddytls.TLS{CertificatesRaw: make(caddy.ModuleMap)}

	var al caddytls.AutomateLoader

	for i, sblock := range inputServerBlocks {
		server := new(layer4.Server)

		var hostnames []string

		for _, arg := range sblock.Keys {
			address, err := httpcaddyfile.ParseAddress(arg)
			if err != nil {
				return nil, nil, err
			}
			hostnames = append(hostnames, address.Host)
			server.Listen = append(server.Listen, arg)
		}

		for _, segment := range sblock.Segments {
			d := caddyfile.NewDispenser(segment)

			for d.Next() {
				switch d.Val() {
				case "echo":
					server.Routes = append(server.Routes, &layer4.Route{
						HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(new(l4echo.Handler), "handler", "echo", nil)},
					})

				case "tls":
					handler, err := parseTLS(d)
					if err != nil {
						return nil, nil, err
					}
					server.Routes = append(server.Routes, &layer4.Route{
						HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(handler, "handler", "tls", nil)},
					})

					// TODO: only hostnames which are valid for tls
					al = append(al, hostnames...)

				case "proxy":
					handler, err := parseProxy(d)
					if err != nil {
						return nil, nil, err
					}
					server.Routes = append(server.Routes, &layer4.Route{
						HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(handler, "handler", "proxy", nil)},
					})

				case "proxy_protocol":
					handler, err := parseProxyProtocol(d)
					if err != nil {
						return nil, nil, err
					}
					server.Routes = append(server.Routes, &layer4.Route{
						HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(handler, "handler", "proxy_protocol", nil)},
					})
				}
			}
		}

		l4app.Servers["srv"+strconv.Itoa(i)] = server
	}

	if len(al) > 0 {
		tlsApp.CertificatesRaw["automate"] = caddyconfig.JSON(al, &warnings)
	}

	cfg := &caddy.Config{AppsRaw: make(caddy.ModuleMap)}

	if len(l4app.Servers) > 0 {
		cfg.AppsRaw["layer4"] = caddyconfig.JSON(l4app, nil)
	}
	if !reflect.DeepEqual(tlsApp, &caddytls.TLS{CertificatesRaw: make(caddy.ModuleMap)}) {
		cfg.AppsRaw["tls"] = caddyconfig.JSON(tlsApp, &warnings)
	}

	return cfg, warnings, nil
}

// TODO: reuse httpcaddyfile.parseTLS somehow
func parseTLS(d *caddyfile.Dispenser) (*l4tls.Handler, error) {
	h := new(l4tls.Handler)

	cp := new(caddytls.ConnectionPolicy)

	for d.NextBlock(0) {
		switch d.Val() {
		case "alpn":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return nil, d.ArgErr()
			}
			cp.ALPN = args
		}
	}

	h.ConnectionPolicies = append(h.ConnectionPolicies, cp)

	return h, nil
}

func parseProxy(d *caddyfile.Dispenser) (*l4proxy.Handler, error) {
	h := new(l4proxy.Handler)

	appendUpstream := func(addresses ...string) {
		for _, addr := range addresses {
			h.Upstreams = append(h.Upstreams, &l4proxy.Upstream{
				Dial: []string{addr},
			})
		}
	}

	appendUpstream(d.RemainingArgs()...)

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "to":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return nil, d.ArgErr()
			}
			appendUpstream(args...)

		case "lb_policy":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			if h.LoadBalancing != nil && h.LoadBalancing.SelectionPolicyRaw != nil {
				return nil, d.Err("load balancing selection policy already specified")
			}
			if h.LoadBalancing == nil {
				h.LoadBalancing = new(l4proxy.LoadBalancing)
			}

			name := d.Val()
			modID := "layer4.proxy.selection_policies." + name
			mod, err := UnmarshalL4proxySelectionModule(d, modID)
			if err != nil {
				return nil, err
			}

			sel, ok := mod.(l4proxy.Selector)
			if !ok {
				return nil, d.Errf("module %s (%T) is not a l4proxy.Selector", modID, mod)
			}
			h.LoadBalancing.SelectionPolicyRaw = caddyconfig.JSONModuleObject(sel, "policy", name, nil)

		case "lb_try_duration":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			if h.LoadBalancing == nil {
				h.LoadBalancing = new(l4proxy.LoadBalancing)
			}

			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, d.Errf("bad duration value %s: %v", d.Val(), err)
			}
			h.LoadBalancing.TryDuration = caddy.Duration(dur)

		case "lb_try_interval":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			if h.LoadBalancing == nil {
				h.LoadBalancing = new(l4proxy.LoadBalancing)
			}

			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, d.Errf("bad interval value '%s': %v", d.Val(), err)
			}
			h.LoadBalancing.TryInterval = caddy.Duration(dur)

		case "health_port":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(l4proxy.HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(l4proxy.ActiveHealthChecks)
			}

			portNum, err := strconv.Atoi(d.Val())
			if err != nil {
				return nil, d.Errf("bad port number '%s': %v", d.Val(), err)
			}
			h.HealthChecks.Active.Port = portNum

		case "health_interval":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(l4proxy.HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(l4proxy.ActiveHealthChecks)
			}

			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, d.Errf("bad interval value %s: %v", d.Val(), err)
			}
			h.HealthChecks.Active.Interval = caddy.Duration(dur)

		case "health_timeout":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(l4proxy.HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(l4proxy.ActiveHealthChecks)
			}

			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, d.Errf("bad timeout value %s: %v", d.Val(), err)
			}
			h.HealthChecks.Active.Timeout = caddy.Duration(dur)

		case "proxy_protocol":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			h.ProxyProtocol = d.Val()
		}
	}

	return h, nil
}

// UnmarshalL4proxySelectionModule is like `caddyfile.UnmarshalModule`, but for
// l4proxy's selection modules, which do not implement `caddyfile.Unmarshaler` yet.
func UnmarshalL4proxySelectionModule(d *caddyfile.Dispenser, moduleID string) (caddy.Module, error) {
	mod, err := caddy.GetModule(moduleID)
	if err != nil {
		return nil, d.Errf("getting module named '%s': %v", moduleID, err)
	}
	inst := mod.New()

	if err = UnmarshalL4ProxySelectionCaddyfile(inst, d.NewFromNextSegment()); err != nil {
		return nil, err
	}
	return inst, nil
}

func UnmarshalL4ProxySelectionCaddyfile(inst caddy.Module, d *caddyfile.Dispenser) error {
	switch sel := inst.(type) {
	case *l4proxy.RandomSelection,
		*l4proxy.LeastConnSelection,
		*l4proxy.RoundRobinSelection,
		*l4proxy.FirstSelection,
		*l4proxy.IPHashSelection:

		for d.Next() {
			if d.NextArg() {
				return d.ArgErr()
			}
		}

	case *l4proxy.RandomChoiceSelection:
		for d.Next() {
			if !d.NextArg() {
				return d.ArgErr()
			}
			chooseStr := d.Val()
			choose, err := strconv.Atoi(chooseStr)
			if err != nil {
				return d.Errf("invalid choice value '%s': %v", chooseStr, err)
			}
			sel.Choose = choose
		}
	}

	return nil
}

func parseProxyProtocol(d *caddyfile.Dispenser) (*l4proxyprotocol.Handler, error) {
	h := new(l4proxyprotocol.Handler)

	// No same-line options are supported
	if len(d.RemainingArgs()) > 0 {
		return nil, d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "timeout":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			timeout, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, d.Errf("parsing proxy_protocol timeout duration: %v", err)
			}
			h.Timeout = caddy.Duration(timeout)

		case "allow":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return nil, d.ArgErr()
			}
			h.Allow = append(h.Allow, args...)

		default:
			return nil, d.ArgErr()
		}
	}

	return h, nil
}
