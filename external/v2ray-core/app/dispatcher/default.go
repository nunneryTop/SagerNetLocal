package dispatcher

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

import (
	"context"
	"strings"
	"sync"
	"time"

	core "github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/log"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/protocol"
	"github.com/v2fly/v2ray-core/v4/common/protocol/bittorrent"
	"github.com/v2fly/v2ray-core/v4/common/protocol/dns"
	"github.com/v2fly/v2ray-core/v4/common/protocol/http"
	"github.com/v2fly/v2ray-core/v4/common/protocol/quic"
	"github.com/v2fly/v2ray-core/v4/common/protocol/tls"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/features/outbound"
	"github.com/v2fly/v2ray-core/v4/features/policy"
	"github.com/v2fly/v2ray-core/v4/features/routing"
	routing_session "github.com/v2fly/v2ray-core/v4/features/routing/session"
	"github.com/v2fly/v2ray-core/v4/features/stats"
	"github.com/v2fly/v2ray-core/v4/transport"
	"github.com/v2fly/v2ray-core/v4/transport/pipe"
)

var errSniffingTimeout = newError("timeout on sniffing")

type cachedReader struct {
	sync.Mutex
	reader *pipe.Reader
	cache  buf.MultiBuffer
}

func (r *cachedReader) Cache(b *buf.Buffer) {
	mb, _ := r.reader.ReadMultiBufferTimeout(time.Millisecond * 100)
	r.Lock()
	if !mb.IsEmpty() {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	b.Clear()
	rawBytes := b.Extend(buf.Size)
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb
	}

	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBufferTimeout(timeout)
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	r.Unlock()
	r.reader.Interrupt()
}

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
	ohm    outbound.Manager
	router routing.Router
	policy policy.Manager
	stats  stats.Manager
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
			return d.Init(config.(*Config), om, router, pm, sm)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
	d.ohm = om
	d.router = router
	d.policy = pm
	d.stats = sm
	return nil
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (*DefaultDispatcher) Close() error { return nil }

func (d *DefaultDispatcher) getLink(ctx context.Context) (*transport.Link, *transport.Link) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	if user != nil && len(user.Email) > 0 {
		p := d.policy.ForLevel(user.Level)
		if p.Stats.UserUplink {
			name := "user>>>" + user.Email + ">>>traffic>>>uplink"
			if c, _ := stats.GetOrRegisterCounter(d.stats, name); c != nil {
				inboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  inboundLink.Writer,
				}
			}
		}
		if p.Stats.UserDownlink {
			name := "user>>>" + user.Email + ">>>traffic>>>downlink"
			if c, _ := stats.GetOrRegisterCounter(d.stats, name); c != nil {
				outboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  outboundLink.Writer,
				}
			}
		}
	}

	return inboundLink, outboundLink
}

func shouldOverride(result SniffResult, domainOverride []string) bool {
	if result.Domain() == "" {
		return false
	}
	protocolString := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		protocolString = resComp.ProtocolForDomainResult()
	}
	for _, p := range domainOverride {
		if strings.HasPrefix(protocolString, p) {
			return true
		}
		if resultSubset, ok := result.(SnifferIsProtoSubsetOf); ok {
			if resultSubset.IsProtoSubsetOf(p) {
				return true
			}
		}
	}
	return false
}

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	ob := &session.Outbound{
		Target: destination,
	}
	ctx = session.ContextWithOutbound(ctx, ob)

	inbound, outbound := d.getLink(ctx)
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	sniffingRequest := content.SniffingRequest
	if destination.Network == net.Network_TCP && !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func() {
			cReader := &cachedReader{
				reader: outbound.Reader.(*pipe.Reader),
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network, sniffingRequest.Enabled)
			if err == nil {
				content.Protocol = result.Protocol()
				if sniffingRequest.Callback != nil {
					sniffingRequest.Callback(result.Protocol(), result.Domain())
				}
				domain := result.Domain()
				if domain != "" {
					newError("sniffed domain: [", result.Protocol(), "] ", domain).WriteToLog(session.ExportIDToError(ctx))
				}
				if shouldOverride(result, sniffingRequest.OverrideDestinationForProtocol) {
					destination.Address = net.ParseAddress(domain)
					if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
						ob.RouteTarget = destination
					} else {
						ob.Target = destination
					}
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}()
	}

	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	if !destination.IsValid() {
		return newError("Dispatcher: Invalid destination.")
	}
	ob := &session.Outbound{
		Target: destination,
	}
	ctx = session.ContextWithOutbound(ctx, ob)
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	sniffingRequest := content.SniffingRequest
	if destination.Network == net.Network_TCP && !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func() {
			cReader := &cachedReader{
				reader: outbound.Reader.(*pipe.Reader),
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network, sniffingRequest.Enabled)
			if err == nil {
				content.Protocol = result.Protocol()
				if sniffingRequest.Callback != nil {
					sniffingRequest.Callback(result.Protocol(), result.Domain())
				}
				domain := result.Domain()
				if domain != "" {
					newError("sniffed domain: [", result.Protocol(), "] ", domain).WriteToLog(session.ExportIDToError(ctx))
				}
				if shouldOverride(result, sniffingRequest.OverrideDestinationForProtocol) {
					destination.Address = net.ParseAddress(domain)
					if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
						ob.RouteTarget = destination
					} else {
						ob.Target = destination
					}
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}()
	}
	return nil
}

var defaultSniffers = &Sniffer{
	sniffer: []protocolSnifferWithMetadata{
		{func(c context.Context, b []byte) (SniffResult, error) { return http.SniffHTTP(b) }, false, net.Network_TCP},
		{func(c context.Context, b []byte) (SniffResult, error) { return tls.SniffTLS(b) }, false, net.Network_TCP},
		{func(c context.Context, b []byte) (SniffResult, error) { return quic.SniffQUIC(b) }, false, net.Network_UDP},
		{func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffBittorrent(b) }, false, net.Network_TCP},
		{func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffUTP(b) }, false, net.Network_UDP},
		{func(c context.Context, b []byte) (SniffResult, error) { return dns.SniffDNS(b) }, false, net.Network_UDP},
		{func(c context.Context, b []byte) (SniffResult, error) { return dns.SniffTCPDNS(b) }, false, net.Network_TCP},
	},
}

var udpOnlyDnsSniffers = &Sniffer{
	sniffer: []protocolSnifferWithMetadata{
		{func(c context.Context, b []byte) (SniffResult, error) { return dns.SniffDNS(b) }, false, net.Network_UDP},
	},
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network, enabled bool) (SniffResult, error) {
	payload := buf.New()
	defer payload.Release()

	contentResult, contentErr := func() (SniffResult, error) {
		totalAttempt := 0
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				totalAttempt++
				if totalAttempt > 2 {
					return nil, errSniffingTimeout
				}

				cReader.Cache(payload)
				if !payload.IsEmpty() {
					var sniffers *Sniffer
					if enabled {
						sniffers = defaultSniffers
					} else {
						sniffers = udpOnlyDnsSniffers
					}
					result, err := sniffers.Sniff(ctx, payload.Bytes(), network)
					if err != common.ErrNoClue {
						return result, err
					}
				}
				if payload.IsFull() {
					return nil, errUnknownContent
				}
			}
		}
	}()
	return contentResult, contentErr
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {
	var handler outbound.Handler

	if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		if h := d.ohm.GetHandler(forcedOutboundTag); h != nil {
			newError("taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]").WriteToLog(session.ExportIDToError(ctx))
			handler = h
		} else {
			newError("non existing tag for platform initialized detour: ", forcedOutboundTag).AtError().WriteToLog(session.ExportIDToError(ctx))
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
	} else if d.router != nil {
		if route, err := d.router.PickRoute(routing_session.AsRoutingContext(ctx)); err == nil {
			tag := route.GetOutboundTag()
			if h := d.ohm.GetHandler(tag); h != nil {
				newError("taking detour [", tag, "] for [", destination, "]").WriteToLog(session.ExportIDToError(ctx))
				handler = h
			} else {
				newError("non existing tag: ", tag).AtWarning().WriteToLog(session.ExportIDToError(ctx))
			}
		} else {
			newError("default route for ", destination).WriteToLog(session.ExportIDToError(ctx))
		}
	}

	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}

	if handler == nil {
		newError("default outbound handler not exist").WriteToLog(session.ExportIDToError(ctx))
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}

	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := handler.Tag(); tag != "" {
			accessMessage.Detour = tag
		}
		log.Record(accessMessage)
	}

	handler.Dispatch(ctx, link)
}
