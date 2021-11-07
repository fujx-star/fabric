# Fabric交易源码分析

在用git工具将 https://github.com/hyperledger/fabric.git 克隆到本地时，可能由于项目较大的原因，总是出现各种各样的问题，所以索性在Github上面分析，截图来自于github，而非本地项目。

Fabric的项目代码个人感觉比较分散，没有像以太坊源码那样不同文件各司其职（也可能是我对源码还不够熟悉的缘故），所以基于交易流程分析。

Fabric交易从产生到记入账本大致分为四个部分：（1）客户端向背书节点发送交易提案请求（2）背书节点对交易提案进行签名背书并将结果返回（3）客户端向排序服务提交交易（4）排序服务节点生成区块。我根据这四个部分的顺序依次进行分析。

- #### 客户端向背书节点发送交易提案请求

首先要得到一个Endorser客户端。一个普通客户端结构体这样定义：

~~~
//internal/peer/common/common.go

type CommonClient struct {
	clientConfig comm.ClientConfig
	address      string
}
~~~

newCommonClient函数用来返回一个根据地址和配置参数创建的普通客户端：

~~~
//internal/peer/common/common.go

func newCommonClient(address string, clientConfig comm.ClientConfig) (*CommonClient, error) {
	return &CommonClient{
		clientConfig: clientConfig,
		address:      address,
	}, nil
}
~~~

可以看到PeerClient结构体实际结构与CommonClient一致：

~~~
//internal/peer/common/peerclient.go

// PeerClient represents a client for communicating with a peer
type PeerClient struct {
	*CommonClient
}
~~~


GetEndorserClient函数调用newPeerClient函数得到一个新的客户端peerClient，并且根据该客户端中的Endorser方法返回了一个Endorser客户端：

~~~
//internal/peer/common/peerclient.go

// GetEndorserClient returns a new endorser client. If the both the address and
// tlsRootCertFile are not provided, the target values for the client are taken
// from the configuration settings for "peer.address" and
// "peer.tls.rootcert.file"
func GetEndorserClient(address, tlsRootCertFile string) (pb.EndorserClient, error) {
	peerClient, err := newPeerClient(address, tlsRootCertFile)
	if err != nil {
		return nil, err
	}
	return peerClient.Endorser()
}
~~~

Endorser方法又调用了NewEndorserClient函数，它最终返回了一个ClinetConn连接，意味着一个Endorser客户端建立成功：

~~~
//internal/peer/common/peerclient.go

// Endorser returns a client for the Endorser service
func (pc *PeerClient) Endorser() (pb.EndorserClient, error) {
	conn, err := pc.CommonClient.clientConfig.Dial(pc.address)
	if err != nil {
		return nil, errors.WithMessagef(err, "endorser client failed to connect to %s", pc.address)
	}
	return pb.NewEndorserClient(conn), nil
}
~~~

~~~
//vendor/github.com/hyperledger/fabric-protos-go/peer/peer.pb.go

type endorserClient struct {
	cc *grpc.ClientConn
}

func NewEndorserClient(cc *grpc.ClientConn) EndorserClient {
	return &endorserClient{cc}
}
~~~

EndorserClient是为了背书服务而定义的客户端接口。可以看到关于EndorserClient接口的定义：

~~~
//vendor/github.com/hyperledger/fabric-protos-go/peer/peer.pb.go

// EndorserClient is the client API for Endorser service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type EndorserClient interface {
	ProcessProposal(ctx context.Context, in *SignedProposal, opts ...grpc.CallOption) (*ProposalResponse, error)
}
~~~

这个接口调用了ProcessProposal函数，用来执行交易中的智能合约。ProcessProposal函数新建了一个响应体后，将交易参数ctx，智能合约名称和合约输入作为参数传递给函数Invoke：

~~~
//vendor/github.com/hyperledger/fabric-protos-go/peer/peer.pb.go

func (c *endorserClient) ProcessProposal(ctx context.Context, in *SignedProposal, opts ...grpc.CallOption) (*ProposalResponse, error) {
	out := new(ProposalResponse)
	err := c.cc.Invoke(ctx, "/protos.Endorser/ProcessProposal", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}
~~~

Invoke函数则调用CheckInvocation函数得到了智能合约的ID和类型，并在检查了各参数的合法性之后将execute函数执行的结果（即正确或错误信息）返回到ProcessProposal函数中定义的err变量：

~~~
//core/chaincode/chaincode_support.go

func (cs *ChaincodeSupport) Invoke(txParams *ccprovider.TransactionParams, chaincodeName string, input *pb.ChaincodeInput) (*pb.ChaincodeMessage, error) {
	ccid, cctype, err := cs.CheckInvocation(txParams, chaincodeName, input)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid invocation")
	}

	h, err := cs.Launch(ccid)
	if err != nil {
		return nil, err
	}

	return cs.execute(cctype, txParams, chaincodeName, input, h)
}
~~~

而execute函数则主要对智能合约相关信息（Type, Payload, Txid, ChannelId）做了说明并将环境参数、合约名称、合约相关信息作为参数传递给Execute函数使之调用智能合约，并传递了timeout参数作为执行是否超时的接口：

~~~
//core/chaincode/chaincode_support.go

// execute executes a transaction and waits for it to complete until a timeout value.
func (cs *ChaincodeSupport) execute(cctyp pb.ChaincodeMessage_Type, txParams *ccprovider.TransactionParams, namespace string, input *pb.ChaincodeInput, h *Handler) (*pb.ChaincodeMessage, error) {
	input.Decorations = txParams.ProposalDecorations

	payload, err := proto.Marshal(input)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create chaincode message")
	}

	ccMsg := &pb.ChaincodeMessage{
		Type:      cctyp,
		Payload:   payload,
		Txid:      txParams.TxID,
		ChannelId: txParams.ChannelID,
	}

	timeout := cs.executeTimeout(namespace, input)
	ccresp, err := h.Execute(txParams, namespace, ccMsg, timeout)
	if err != nil {
		return nil, errors.WithMessage(err, "error sending")
	}

	return ccresp, nil
}
~~~

Execute函数调用了processChaincodeExecutionResult函数并返回最初的响应体，此时Invoke调用结束，ProcessProposal中的err变量得到了智能合约的执行结果，ProcessProposal返回结果并结束。

~~~
//core/chaincode/chaincode_support.go

// Execute invokes chaincode and returns the original response.
func (cs *ChaincodeSupport) Execute(txParams *ccprovider.TransactionParams, chaincodeName string, input *pb.ChaincodeInput) (*pb.Response, *pb.ChaincodeEvent, error) {
	resp, err := cs.Invoke(txParams, chaincodeName, input)
	return processChaincodeExecutionResult(txParams.TxID, chaincodeName, resp, err)
}

func processChaincodeExecutionResult(txid, ccName string, resp *pb.ChaincodeMessage, err error) (*pb.Response, *pb.ChaincodeEvent, error) {
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to execute transaction %s", txid)
	}
	if resp == nil {
		return nil, nil, errors.Errorf("nil response from transaction %s", txid)
	}

	if resp.ChaincodeEvent != nil {
		resp.ChaincodeEvent.ChaincodeId = ccName
		resp.ChaincodeEvent.TxId = txid
	}

	switch resp.Type {
	case pb.ChaincodeMessage_COMPLETED:
		res := &pb.Response{}
		err := proto.Unmarshal(resp.Payload, res)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to unmarshal response for transaction %s", txid)
		}
		return res, resp.ChaincodeEvent, nil

	case pb.ChaincodeMessage_ERROR:
		return nil, resp.ChaincodeEvent, errors.Errorf("transaction returned with failure: %s", resp.Payload)

	default:
		return nil, nil, errors.Errorf("unexpected response type %d for transaction %s", resp.Type, txid)
	}
}
~~~

- #### 背书节点对交易提案进行签名背书并将结果返回

与EndorserClient类似地，以下是Endorser结构体的定义：

~~~
//core/endorser/endorser.go

// Endorser provides the Endorser service ProcessProposal
type Endorser struct {
	ChannelFetcher         ChannelFetcher
	LocalMSP               msp.IdentityDeserializer
	PrivateDataDistributor PrivateDataDistributor
	Support                Support
	PvtRWSetAssembler      PvtRWSetAssembler
	Metrics                *Metrics
}
~~~

在该文件中存在ProcessProposal函数，作为Endorser.go文件中最重要的接口:

~~~
//core/endorser/endorser.go

// ProcessProposal process the Proposal
func (e *Endorser) ProcessProposal(ctx context.Context, signedProp *pb.SignedProposal) (*pb.ProposalResponse, error) {
	// start time for computing elapsed time metric for successfully endorsed proposals
	startTime := time.Now()
	e.Metrics.ProposalsReceived.Add(1)

	addr := util.ExtractRemoteAddress(ctx)
	endorserLogger.Debug("request from", addr)

	// variables to capture proposal duration metric
	success := false

	up, err := UnpackProposal(signedProp)
	if err != nil {
		e.Metrics.ProposalValidationFailed.Add(1)
		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, err
	}

	var channel *Channel
	if up.ChannelID() != "" {
		channel = e.ChannelFetcher.Channel(up.ChannelID())
		if channel == nil {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: fmt.Sprintf("channel '%s' not found", up.ChannelHeader.ChannelId)}}, nil
		}
	} else {
		channel = &Channel{
			IdentityDeserializer: e.LocalMSP,
		}
	}

	// 0 -- check and validate
	err = e.preProcess(up, channel)
	if err != nil {
		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, err
	}

	defer func() {
		meterLabels := []string{
			"channel", up.ChannelHeader.ChannelId,
			"chaincode", up.ChaincodeName,
			"success", strconv.FormatBool(success),
		}
		e.Metrics.ProposalDuration.With(meterLabels...).Observe(time.Since(startTime).Seconds())
	}()

	pResp, err := e.ProcessProposalSuccessfullyOrError(up)
	if err != nil {
		endorserLogger.Warnw("Failed to invoke chaincode", "channel", up.ChannelHeader.ChannelId, "chaincode", up.ChaincodeName, "error", err.Error())
		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, nil
	}

	if pResp.Endorsement != nil || up.ChannelHeader.ChannelId == "" {
		// We mark the tx as successful only if it was successfully endorsed, or
		// if it was a system chaincode on a channel-less channel and therefore
		// cannot be endorsed.
		success = true

		// total failed proposals = ProposalsReceived-SuccessfulProposals
		e.Metrics.SuccessfulProposals.Add(1)
	}
	return pResp, nil
}
~~~

首先，ProcessProposal调用了UnpackProposal函数检查能否将传进来的交易提案参数singnedProp进行解包.UnpackProposal函数对交易提案进行了大量合法性检查,如果通过了合法性检查，函数返回一个解包后的提案；如果交易提案不合法，函数最后返回错误信息：

~~~
//core/endorser/msgvalidation.go

// UnpackProposal creates an an *UnpackedProposal which is guaranteed to have
// no zero-ed fields or it returns an error.
func UnpackProposal(signedProp *peer.SignedProposal) (*UnpackedProposal, error) {
	prop, err := protoutil.UnmarshalProposal(signedProp.ProposalBytes)
	if err != nil {
		return nil, err
	}

	hdr, err := protoutil.UnmarshalHeader(prop.Header)
	if err != nil {
		return nil, err
	}

	chdr, err := protoutil.UnmarshalChannelHeader(hdr.ChannelHeader)
	if err != nil {
		return nil, err
	}

	shdr, err := protoutil.UnmarshalSignatureHeader(hdr.SignatureHeader)
	if err != nil {
		return nil, err
	}

	chaincodeHdrExt, err := protoutil.UnmarshalChaincodeHeaderExtension(chdr.Extension)
	if err != nil {
		return nil, err
	}

	if chaincodeHdrExt.ChaincodeId == nil {
		return nil, errors.Errorf("ChaincodeHeaderExtension.ChaincodeId is nil")
	}

	if chaincodeHdrExt.ChaincodeId.Name == "" {
		return nil, errors.Errorf("ChaincodeHeaderExtension.ChaincodeId.Name is empty")
	}

	cpp, err := protoutil.UnmarshalChaincodeProposalPayload(prop.Payload)
	if err != nil {
		return nil, err
	}

	cis, err := protoutil.UnmarshalChaincodeInvocationSpec(cpp.Input)
	if err != nil {
		return nil, err
	}

	if cis.ChaincodeSpec == nil {
		return nil, errors.Errorf("chaincode invocation spec did not contain chaincode spec")
	}

	if cis.ChaincodeSpec.Input == nil {
		return nil, errors.Errorf("chaincode input did not contain any input")
	}

	cppNoTransient := &peer.ChaincodeProposalPayload{Input: cpp.Input, TransientMap: nil}
	ppBytes, err := proto.Marshal(cppNoTransient)
	if err != nil {
		return nil, errors.WithMessage(err, "could not marshal non-transient portion of payload")
	}

	// TODO, this was preserved from the proputils stuff, but should this be BCCSP?

	// The proposal hash is the hash of the concatenation of:
	// 1) The serialized Channel Header object
	// 2) The serialized Signature Header object
	// 3) The hash of the part of the chaincode proposal payload that will go to the tx
	// (ie, the parts without the transient data)
	propHash := sha256.New()
	propHash.Write(hdr.ChannelHeader)
	propHash.Write(hdr.SignatureHeader)
	propHash.Write(ppBytes)

	return &UnpackedProposal{
		SignedProposal:  signedProp,
		Proposal:        prop,
		ChannelHeader:   chdr,
		SignatureHeader: shdr,
		ChaincodeName:   chaincodeHdrExt.ChaincodeId.Name,
		Input:           cis.ChaincodeSpec.Input,
		ProposalHash:    propHash.Sum(nil)[:],
	}, nil
}
~~~

之后，ProcessProposal调用了Channel函数对解包后的交易提案的ChannelID进行检查，返回错误信息或绑定本地频道号.以下是ChannelFetcher结构体以及Channel函数代码的定义：

~~~
//core/endorser/fake/channel_fetcher.go

type ChannelFetcher struct {
	ChannelStub        func(string) *endorser.Channel
	channelMutex       sync.RWMutex
	channelArgsForCall []struct {
		arg1 string
	}
	channelReturns struct {
		result1 *endorser.Channel
	}
	channelReturnsOnCall map[int]struct {
		result1 *endorser.Channel
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ChannelFetcher) Channel(arg1 string) *endorser.Channel {
	fake.channelMutex.Lock()
	ret, specificReturn := fake.channelReturnsOnCall[len(fake.channelArgsForCall)]
	fake.channelArgsForCall = append(fake.channelArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("Channel", []interface{}{arg1})
	fake.channelMutex.Unlock()
	if fake.ChannelStub != nil {
		return fake.ChannelStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.channelReturns
	return fakeReturns.result1
}

~~~

验证通过后，ProcessProposal函数进行了预执行，调用了preProcess函数.preProcess函数主要进行了了tx交易头检查（消息是否有效）、唯一性检查和应用智能合约的通道策略检查，若检查通过则返回一个空值，否则返回错误信息：

~~~
//core/endorser/endorser.go

// preProcess checks the tx proposal headers, uniqueness and ACL
func (e *Endorser) preProcess(up *UnpackedProposal, channel *Channel) error {
	// at first, we check whether the message is valid

	err := up.Validate(channel.IdentityDeserializer)
	if err != nil {
		e.Metrics.ProposalValidationFailed.Add(1)
		return errors.WithMessage(err, "error validating proposal")
	}

	if up.ChannelHeader.ChannelId == "" {
		// chainless proposals do not/cannot affect ledger and cannot be submitted as transactions
		// ignore uniqueness checks; also, chainless proposals are not validated using the policies
		// of the chain since by definition there is no chain; they are validated against the local
		// MSP of the peer instead by the call to ValidateUnpackProposal above
		return nil
	}

	// labels that provide context for failure metrics
	meterLabels := []string{
		"channel", up.ChannelHeader.ChannelId,
		"chaincode", up.ChaincodeName,
	}

	// Here we handle uniqueness check and ACLs for proposals targeting a chain
	// Notice that ValidateProposalMessage has already verified that TxID is computed properly
	if _, err = e.Support.GetTransactionByID(up.ChannelHeader.ChannelId, up.ChannelHeader.TxId); err == nil {
		// increment failure due to duplicate transactions. Useful for catching replay attacks in
		// addition to benign retries
		e.Metrics.DuplicateTxsFailure.With(meterLabels...).Add(1)
		return errors.Errorf("duplicate transaction found [%s]. Creator [%x]", up.ChannelHeader.TxId, up.SignatureHeader.Creator)
	}

	// check ACL only for application chaincodes; ACLs
	// for system chaincodes are checked elsewhere
	if !e.Support.IsSysCC(up.ChaincodeName) {
		// check that the proposal complies with the Channel's writers
		if err = e.Support.CheckACL(up.ChannelHeader.ChannelId, up.SignedProposal); err != nil {
			e.Metrics.ProposalACLCheckFailed.With(meterLabels...).Add(1)
			return err
		}
	}

	return nil
}

~~~

检查工作全部完成后，ProcessProposal函数将解包后的提案变量up传递给ProcessProposalSuccessfullyOrError函数，使其最终执行提案.ProcessProposalSuccessfullyOrError函数实际上也进行了一系列的错误判断并调用simulateProposal函数对提案做了模拟执行，如果上述工作都没有出错，那么则调用EndorseWithPlugin函数执行背书操作：

~~~
//core/endorser/endorser.go

func (e *Endorser) ProcessProposalSuccessfullyOrError(up *UnpackedProposal) (*pb.ProposalResponse, error) {
	txParams := &ccprovider.TransactionParams{
		ChannelID:  up.ChannelHeader.ChannelId,
		TxID:       up.ChannelHeader.TxId,
		SignedProp: up.SignedProposal,
		Proposal:   up.Proposal,
	}

	logger := decorateLogger(endorserLogger, txParams)

	if acquireTxSimulator(up.ChannelHeader.ChannelId, up.ChaincodeName) {
		txSim, err := e.Support.GetTxSimulator(up.ChannelID(), up.TxID())
		if err != nil {
			return nil, err
		}

		// txsim acquires a shared lock on the stateDB. As this would impact the block commits (i.e., commit
		// of valid write-sets to the stateDB), we must release the lock as early as possible.
		// Hence, this txsim object is closed in simulateProposal() as soon as the tx is simulated and
		// rwset is collected before gossip dissemination if required for privateData. For safety, we
		// add the following defer statement and is useful when an error occur. Note that calling
		// txsim.Done() more than once does not cause any issue. If the txsim is already
		// released, the following txsim.Done() simply returns.
		defer txSim.Done()

		hqe, err := e.Support.GetHistoryQueryExecutor(up.ChannelID())
		if err != nil {
			return nil, err
		}

		txParams.TXSimulator = txSim
		txParams.HistoryQueryExecutor = hqe
	}

	cdLedger, err := e.Support.ChaincodeEndorsementInfo(up.ChannelID(), up.ChaincodeName, txParams.TXSimulator)
	if err != nil {
		return nil, errors.WithMessagef(err, "make sure the chaincode %s has been successfully defined on channel %s and try again", up.ChaincodeName, up.ChannelID())
	}

	// 1 -- simulate
	res, simulationResult, ccevent, ccInterest, err := e.simulateProposal(txParams, up.ChaincodeName, up.Input)
	if err != nil {
		return nil, errors.WithMessage(err, "error in simulation")
	}

	cceventBytes, err := CreateCCEventBytes(ccevent)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal chaincode event")
	}

	prpBytes, err := protoutil.GetBytesProposalResponsePayload(up.ProposalHash, res, simulationResult, cceventBytes, &pb.ChaincodeID{
		Name:    up.ChaincodeName,
		Version: cdLedger.Version,
	})
	if err != nil {
		logger.Warning("Failed marshaling the proposal response payload to bytes", err)
		return nil, errors.WithMessage(err, "failed to create the proposal response")
	}

	// if error, capture endorsement failure metric
	meterLabels := []string{
		"channel", up.ChannelID(),
		"chaincode", up.ChaincodeName,
	}

	switch {
	case res.Status >= shim.ERROR:
		return &pb.ProposalResponse{
			Response: res,
			Payload:  prpBytes,
			Interest: ccInterest,
		}, nil
	case up.ChannelID() == "":
		// Chaincode invocations without a channel ID is a broken concept
		// that should be removed in the future.  For now, return unendorsed
		// success.
		return &pb.ProposalResponse{
			Response: res,
		}, nil
	case res.Status >= shim.ERRORTHRESHOLD:
		meterLabels = append(meterLabels, "chaincodeerror", strconv.FormatBool(true))
		e.Metrics.EndorsementsFailed.With(meterLabels...).Add(1)
		logger.Debugf("chaincode error %d", res.Status)
		return &pb.ProposalResponse{
			Response: res,
		}, nil
	}

	escc := cdLedger.EndorsementPlugin

	logger.Debugf("escc for chaincode %s is %s", up.ChaincodeName, escc)

	// Note, mPrpBytes is the same as prpBytes by default endorsement plugin, but others could change it.
	endorsement, mPrpBytes, err := e.Support.EndorseWithPlugin(escc, up.ChannelID(), prpBytes, up.SignedProposal)
	if err != nil {
		meterLabels = append(meterLabels, "chaincodeerror", strconv.FormatBool(false))
		e.Metrics.EndorsementsFailed.With(meterLabels...).Add(1)
		return nil, errors.WithMessage(err, "endorsing with plugin failed")
	}

	return &pb.ProposalResponse{
		Version:     1,
		Endorsement: endorsement,
		Payload:     mPrpBytes,
		Response:    res,
		Interest:    ccInterest,
	}, nil
}
~~~

~~~
//core/endorser/plugin_endorser.go

// EndorseWithPlugin endorses the response with a plugin
func (pe *PluginEndorser) EndorseWithPlugin(pluginName, channelID string, prpBytes []byte, signedProposal *pb.SignedProposal) (*pb.Endorsement, []byte, error) {
	plugin, err := pe.getOrCreatePlugin(PluginName(pluginName), channelID)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "plugin with name %s could not be used", pluginName)
	}

	return plugin.Endorse(prpBytes, signedProposal)
}
~~~

首先，EndorserWithPlugin函数调用getOrCreatePlugin函数得到了插件:

~~~
//core/endorser/plugin_endorser.go

// getOrCreatePlugin returns a plugin instance for the given plugin name and channel
func (pe *PluginEndorser) getOrCreatePlugin(plugin PluginName, channel string) (endorsement.Plugin, error) {
	pluginFactory := pe.PluginFactoryByName(plugin)
	if pluginFactory == nil {
		return nil, errors.Errorf("plugin with name %s wasn't found", plugin)
	}

	pluginsByChannel := pe.getOrCreatePluginChannelMapping(PluginName(plugin), pluginFactory)
	return pluginsByChannel.createPluginIfAbsent(channel)
}
~~~

待函数返回插件后，执行了插件下的Endorse函数，将结果返回并储存在err中：

~~~
//core/handlers/endorsement/plugin/plugin.go

// Endorse signs the given payload(ProposalResponsePayload bytes), and optionally mutates it.
// Returns:
// The Endorsement: A signature over the payload, and an identity that is used to verify the signature
// The payload that was given as input (could be modified within this function)
// Or error on failure
func (e *DefaultEndorsement) Endorse(prpBytes []byte, sp *peer.SignedProposal) (*peer.Endorsement, []byte, error) {
	signer, err := e.SigningIdentityForRequest(sp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed fetching signing identity: %v", err)
	}
	// serialize the signing identity
	identityBytes, err := signer.Serialize()
	if err != nil {
		return nil, nil, fmt.Errorf("could not serialize the signing identity: %v", err)
	}

	// sign the concatenation of the proposal response and the serialized endorser identity with this endorser's key
	signature, err := signer.Sign(append(prpBytes, identityBytes...))
	if err != nil {
		return nil, nil, fmt.Errorf("could not sign the proposal response payload: %v", err)
	}
	endorsement := &peer.Endorsement{Signature: signature, Endorser: identityBytes}
	return endorsement, prpBytes, nil
}
~~~

ProcessProposalSuccessfullyOrError函数根据err结果进行了最后一次错误判断后，将simulateProposal执行的结果res和ccInterest以及EndorserWithPlugin的执行结果endorsement和mPrpBytes注入到变量ProposalResponse中并将其返回给ProcessProposal函数.ProcessProposal函数用临时变量pResp接收ProposalResponse，再将结果提交给Endorser客户端。至此，经背书节点之手的提案签名完成。

- #### 客户端向排序服务提交交易

可以用 GetBroadcastClient函数来得到一个BroadcastGRPC客户端：

~~~
//internal/peer/common/broadcastclient.go

// GetBroadcastClient creates a simple instance of the BroadcastClient interface
func GetBroadcastClient() (BroadcastClient, error) {
	oc, err := NewOrdererClientFromEnv()
	if err != nil {
		return nil, err
	}
	bc, err := oc.Broadcast()
	if err != nil {
		return nil, err
	}

	return &BroadcastGRPCClient{Client: bc}, nil
}
~~~

GetBroadcastClient函数首先调用了NewOrdererClientFromEnv函数来创建一个排序服务客户端oc：

~~~
//internal/peer/common/ordererclient.go

// NewOrdererClientFromEnv creates an instance of an OrdererClient from the
// global Viper instance
func NewOrdererClientFromEnv() (*OrdererClient, error) {
	address, clientConfig, err := configFromEnv("orderer")
	if err != nil {
		return nil, errors.WithMessage(err, "failed to load config for OrdererClient")
	}
	cc, err := newCommonClient(address, clientConfig)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create OrdererClient from config")
	}
	return &OrdererClient{CommonClient: cc}, nil
}
~~~

之后，GetBroadcastClient函数又使用了Broadcast方法：

~~~
//internal/peer/common/ordererclient.go

// Broadcast returns a broadcast client for the AtomicBroadcast service
func (oc *OrdererClient) Broadcast() (ab.AtomicBroadcast_BroadcastClient, error) {
	conn, err := oc.CommonClient.clientConfig.Dial(oc.address)
	if err != nil {
		return nil, errors.WithMessagef(err, "orderer client failed to connect to %s", oc.address)
	}
	// TODO: check to see if we should actually handle error before returning
	return ab.NewAtomicBroadcastClient(conn).Broadcast(context.TODO())
}
~~~

Broadcast函数调用了Dial方法来创建一个新的与oc地址连接的GRPC客户端连接，之后使用该连接作为参数，调用了NewAtomicBroadcastClient函数，返回一个AtomicBroadcast客户端，该客户端可以与排序服务节点连接：

~~~
//internal/pkg/comm/config.go

func (cc ClientConfig) Dial(address string) (*grpc.ClientConn, error) {
	dialOpts, err := cc.DialOptions()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cc.DialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, address, dialOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new connection")
	}
	return conn, nil
}
~~~

~~~
//vendor/github.com/hyperledger/fabric-protos-go/orderer/ab.pb.go

type atomicBroadcastClient struct {
	cc *grpc.ClientConn
}

func NewAtomicBroadcastClient(cc *grpc.ClientConn) AtomicBroadcastClient {
	return &atomicBroadcastClient{cc}
}
~~~

ab.pb.go文件中的Broadcast函数调用NewStream函数，用来生成一个信息流：

~~~
//vendor/google.golang.org/grpc/stream.go

// NewStream creates a new Stream for the client side. This is typically
// called by generated code. ctx is used for the lifetime of the stream.
//
// To ensure resources are not leaked due to the stream returned, one of the following
// actions must be performed:
//
//      1. Call Close on the ClientConn.
//      2. Cancel the context provided.
//      3. Call RecvMsg until a non-nil error is returned. A protobuf-generated
//         client-streaming RPC, for instance, might use the helper function
//         CloseAndRecv (note that CloseSend does not Recv, therefore is not
//         guaranteed to release all resources).
//      4. Receive a non-nil, non-io.EOF error from Header or SendMsg.
//
// If none of the above happen, a goroutine and a context will be leaked, and grpc
// will not call the optionally-configured stats handler with a stats.End message.
func (cc *ClientConn) NewStream(ctx context.Context, desc *StreamDesc, method string, opts ...CallOption) (ClientStream, error) {
	// allow interceptor to see all applicable call options, which means those
	// configured as defaults from dial option as well as per-call options
	opts = combine(cc.dopts.callOptions, opts)

	if cc.dopts.streamInt != nil {
		return cc.dopts.streamInt(ctx, desc, cc, method, newClientStream, opts...)
	}
	return newClientStream(ctx, desc, cc, method, opts...)
}
~~~

文件中也有BroadcastClient接口和结构体定义，其中有发送消息的Send函数和用于接收的Recv函数：

~~~
//vendor/github.com/hyperledger/fabric-protos-go/orderer/ab.pb.go

type AtomicBroadcast_BroadcastClient interface {
	Send(*common.Envelope) error
	Recv() (*BroadcastResponse, error)
	grpc.ClientStream
}

type atomicBroadcastBroadcastClient struct {
	grpc.ClientStream
}
~~~

其中，Send函数调用SendMsg函数在ClientStream信息流上发送消息，Recv函数建立广播应答、从ClientStream接收消息并将应答返回：

~~~
//vendor/github.com/hyperledger/fabric-protos-go/orderer/ab.pb.go

func (x *atomicBroadcastBroadcastClient) Send(m *common.Envelope) error {
	return x.ClientStream.SendMsg(m)
}

func (x *atomicBroadcastBroadcastClient) Recv() (*BroadcastResponse, error) {
	m := new(BroadcastResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}
~~~

以上是BroadcastClient接口实现，除了客户端，也要有服务端定义。下面是BroadcastServer的接口和结构体定义：

~~~
//vendor/github.com/hyperledger/fabric-protos-go/orderer/ab.pb.go

type AtomicBroadcast_BroadcastServer interface {
	Send(*BroadcastResponse) error
	Recv() (*common.Envelope, error)
	grpc.ServerStream
}

type atomicBroadcastBroadcastServer struct {
	grpc.ServerStream
}
~~~

BroadcastServer也有两个方法Send和Recv，分别用来发送和接收消息:

~~~
//vendor/github.com/hyperledger/fabric-protos-go/orderer/ab.pb.go

func (x *atomicBroadcastBroadcastServer) Send(m *BroadcastResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *atomicBroadcastBroadcastServer) Recv() (*common.Envelope, error) {
	m := new(common.Envelope)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}
~~~

除Broadcast外，ab.pb.go文件中也有Deliver方法，接口实现与Broadcast类似。

- #### 排序服务节点生成区块

在orderer/common/server/server.go文件中定义了server结构体：

~~~
//orderer/common/server/server.go

type server struct {
	bh    *broadcast.Handler
	dh    *deliver.Handler
	debug *localconfig.Debug
	*multichannel.Registrar
}
~~~

NewServer方法可以根据广播标的和账本读者创建一个BroadcastServer：

~~~
//orderer/common/server/server.go

// NewServer creates an ab.AtomicBroadcastServer based on the broadcast target and ledger Reader
func NewServer(
	r *multichannel.Registrar,
	metricsProvider metrics.Provider,
	debug *localconfig.Debug,
	timeWindow time.Duration,
	mutualTLS bool,
	expirationCheckDisabled bool,
) ab.AtomicBroadcastServer {
	s := &server{
		dh: deliver.NewHandler(deliverSupport{Registrar: r}, timeWindow, mutualTLS, deliver.NewMetrics(metricsProvider), expirationCheckDisabled),
		bh: &broadcast.Handler{
			SupportRegistrar: broadcastSupport{Registrar: r},
			Metrics:          broadcast.NewMetrics(metricsProvider),
		},
		debug:     debug,
		Registrar: r,
	}
	return s
}
~~~

BroadcastServer可以使用定义好的Broadcast方法，从一个客户端接收一串信息用于排序：

~~~
//orderer/common/server/server.go

// Broadcast receives a stream of messages from a client for ordering
func (s *server) Broadcast(srv ab.AtomicBroadcast_BroadcastServer) error {
	logger.Debugf("Starting new Broadcast handler")
	defer func() {
		if r := recover(); r != nil {
			logger.Criticalf("Broadcast client triggered panic: %s\n%s", r, debug.Stack())
		}
		logger.Debugf("Closing Broadcast stream")
	}()
	return s.bh.Handle(&broadcastMsgTracer{
		AtomicBroadcast_BroadcastServer: srv,
		msgTracer: msgTracer{
			debug:    s.debug,
			function: "Broadcast",
		},
	})
}
~~~

Broadcast函数中调用了几次Debugf函数，Debugf函数调用了Logf函数，用来在调试时在日志中输出信息：

~~~
//vendor/github.com/sirupsen/logrus/logger.go

func (logger *Logger) Debugf(format string, args ...interface{}) {
	logger.Logf(DebugLevel, format, args...)
}
~~~

~~~
//core/chaincode/platforms/golang/testdata/ccmodule/customlogger/customlogger.go

func Logf(msg string, args ...interface{}) {
	fmt.Printf(msg, args...)
}
~~~

最终，Broadcast函数调用Handle函数将结果返回，以下是Handle函数的定义：

~~~
//orderer/common/broadcast/broadcast.go

func (bh *Handler) Handle(srv ab.AtomicBroadcast_BroadcastServer) error {
	addr := util.ExtractRemoteAddress(srv.Context())
	logger.Debugf("Starting new broadcast loop for %s", addr)
	for {
		msg, err := srv.Recv()
		if err == io.EOF {
			logger.Debugf("Received EOF from %s, hangup", addr)
			return nil
		}
		if err != nil {
			logger.Warningf("Error reading from %s: %s", addr, err)
			return err
		}

		resp := bh.ProcessMessage(msg, addr)
		err = srv.Send(resp)
		if resp.Status != cb.Status_SUCCESS {
			return err
		}

		if err != nil {
			logger.Warningf("Error sending to %s: %s", addr, err)
			return err
		}
	}
}
~~~

Handle函数循环调用了Recv函数，将接收到的消息存入msg中，在确认接收无误后，调用了ProcessMessage函数对消息进行处理:

~~~
//orderer/common/broadcast/broadcast.go

// ProcessMessage validates and enqueues a single message
func (bh *Handler) ProcessMessage(msg *cb.Envelope, addr string) (resp *ab.BroadcastResponse) {
	tracker := &MetricsTracker{
		ChannelID: "unknown",
		TxType:    "unknown",
		Metrics:   bh.Metrics,
	}
	defer func() {
		// This looks a little unnecessary, but if done directly as
		// a defer, resp gets the (always nil) current state of resp
		// and not the return value
		tracker.Record(resp)
	}()
	tracker.BeginValidate()

	chdr, isConfig, processor, err := bh.SupportRegistrar.BroadcastChannelSupport(msg)
	if chdr != nil {
		tracker.ChannelID = chdr.ChannelId
		tracker.TxType = cb.HeaderType(chdr.Type).String()
	}
	if err != nil {
		logger.Warningf("[channel: %s] Could not get message processor for serving %s: %s", tracker.ChannelID, addr, err)
		return &ab.BroadcastResponse{Status: cb.Status_BAD_REQUEST, Info: err.Error()}
	}

	if !isConfig {
		logger.Debugf("[channel: %s] Broadcast is processing normal message from %s with txid '%s' of type %s", chdr.ChannelId, addr, chdr.TxId, cb.HeaderType_name[chdr.Type])

		configSeq, err := processor.ProcessNormalMsg(msg)
		if err != nil {
			logger.Warningf("[channel: %s] Rejecting broadcast of normal message from %s because of error: %s", chdr.ChannelId, addr, err)
			return &ab.BroadcastResponse{Status: ClassifyError(err), Info: err.Error()}
		}
		tracker.EndValidate()

		tracker.BeginEnqueue()
		if err = processor.WaitReady(); err != nil {
			logger.Warningf("[channel: %s] Rejecting broadcast of message from %s with SERVICE_UNAVAILABLE: rejected by Consenter: %s", chdr.ChannelId, addr, err)
			return &ab.BroadcastResponse{Status: cb.Status_SERVICE_UNAVAILABLE, Info: err.Error()}
		}

		err = processor.Order(msg, configSeq)
		if err != nil {
			logger.Warningf("[channel: %s] Rejecting broadcast of normal message from %s with SERVICE_UNAVAILABLE: rejected by Order: %s", chdr.ChannelId, addr, err)
			return &ab.BroadcastResponse{Status: cb.Status_SERVICE_UNAVAILABLE, Info: err.Error()}
		}
	} else { // isConfig
		logger.Debugf("[channel: %s] Broadcast is processing config update message from %s", chdr.ChannelId, addr)

		config, configSeq, err := processor.ProcessConfigUpdateMsg(msg)
		if err != nil {
			logger.Warningf("[channel: %s] Rejecting broadcast of config message from %s because of error: %s", chdr.ChannelId, addr, err)
			return &ab.BroadcastResponse{Status: ClassifyError(err), Info: err.Error()}
		}
		tracker.EndValidate()

		tracker.BeginEnqueue()
		if err = processor.WaitReady(); err != nil {
			logger.Warningf("[channel: %s] Rejecting broadcast of message from %s with SERVICE_UNAVAILABLE: rejected by Consenter: %s", chdr.ChannelId, addr, err)
			return &ab.BroadcastResponse{Status: cb.Status_SERVICE_UNAVAILABLE, Info: err.Error()}
		}

		err = processor.Configure(config, configSeq)
		if err != nil {
			logger.Warningf("[channel: %s] Rejecting broadcast of config message from %s with SERVICE_UNAVAILABLE: rejected by Configure: %s", chdr.ChannelId, addr, err)
			return &ab.BroadcastResponse{Status: cb.Status_SERVICE_UNAVAILABLE, Info: err.Error()}
		}
	}

	logger.Debugf("[channel: %s] Broadcast has successfully enqueued message of type %s from %s", chdr.ChannelId, cb.HeaderType_name[chdr.Type], addr)

	return &ab.BroadcastResponse{Status: cb.Status_SUCCESS}
}
~~~

ProcessMessage函数调用调用了BroadcastChannelSupport方法，返回一个频道头：

~~~
//orderer/common/multichannel/registrar.go

// BroadcastChannelSupport returns the message channel header, whether the message is a config update
// and the channel resources for a message or an error if the message is not a message which can
// be processed directly (like CONFIG and ORDERER_TRANSACTION messages)
func (r *Registrar) BroadcastChannelSupport(msg *cb.Envelope) (*cb.ChannelHeader, bool, *ChainSupport, error) {
	chdr, err := protoutil.ChannelHeader(msg)
	if err != nil {
		return nil, false, nil, errors.WithMessage(err, "could not determine channel ID")
	}

	cs := r.GetChain(chdr.ChannelId)
	// New channel creation
	if cs == nil {
		sysChan := r.SystemChannel()
		if sysChan == nil {
			return nil, false, nil, errors.New("channel creation request not allowed because the orderer system channel is not defined")
		}
		cs = sysChan
	}

	isConfig := false
	switch cs.ClassifyMsg(chdr) {
	case msgprocessor.ConfigUpdateMsg:
		isConfig = true
	case msgprocessor.ConfigMsg:
		return chdr, false, nil, errors.New("message is of type that cannot be processed directly")
	default:
	}

	return chdr, isConfig, cs, nil
}
~~~

BoradcastChannelSupport函数将msg参数传递到ChannelHeader方法：

~~~
//protoutil/commonutils.go

// ChannelHeader returns the *cb.ChannelHeader for a given *cb.Envelope.
func ChannelHeader(env *cb.Envelope) (*cb.ChannelHeader, error) {
	if env == nil {
		return nil, errors.New("Invalid envelope payload. can't be nil")
	}

	envPayload, err := UnmarshalPayload(env.Payload)
	if err != nil {
		return nil, err
	}

	if envPayload.Header == nil {
		return nil, errors.New("header not set")
	}

	if envPayload.Header.ChannelHeader == nil {
		return nil, errors.New("channel header not set")
	}

	chdr, err := UnmarshalChannelHeader(envPayload.Header.ChannelHeader)
	if err != nil {
		return nil, errors.WithMessage(err, "error unmarshalling channel header")
	}

	return chdr, nil
}
~~~

ChannelHeader方法首先调用UnmarshalPayload方法，将消息中的Payload参数解码，在进行一系列错误判断之后又调用了UnmarshalChannelHeader方法，对频道头进行解码，检查无误后将频道头返回：

~~~
//protoutil/unmarshalers.go

// UnmarshalPayload unmarshals bytes to a Payload
func UnmarshalPayload(encoded []byte) (*common.Payload, error) {
	payload := &common.Payload{}
	err := proto.Unmarshal(encoded, payload)
	return payload, errors.Wrap(err, "error unmarshalling Payload")
}

// UnmarshalChannelHeader unmarshals bytes to a ChannelHeader
func UnmarshalChannelHeader(bytes []byte) (*common.ChannelHeader, error) {
	chdr := &common.ChannelHeader{}
	err := proto.Unmarshal(bytes, chdr)
	return chdr, errors.Wrap(err, "error unmarshalling ChannelHeader")
}
~~~

BroadcastChannelSupport函数将解码后的频道头存入临时变量chdr中，再将chdr中的ChannelId成员变量作为参数传递给GetChain函数，得到频道存入临时变量cs中：

~~~
//common/deliver/mock/chain_manager.go

func (fake *ChainManager) GetChain(arg1 string) deliver.Chain {
	fake.getChainMutex.Lock()
	ret, specificReturn := fake.getChainReturnsOnCall[len(fake.getChainArgsForCall)]
	fake.getChainArgsForCall = append(fake.getChainArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("GetChain", []interface{}{arg1})
	fake.getChainMutex.Unlock()
	if fake.GetChainStub != nil {
		return fake.GetChainStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.getChainReturns
	return fakeReturns.result1
}
~~~

在进行了错误判断后，以chdr作为参数调用链中定义的方法ClassifyMsg得到该频道中链的配置信息，用来对不同的消息进行分类：

~~~
//orderer/common/broadcast/mock/channel_support.go

func (fake *ChannelSupport) ClassifyMsg(arg1 *common.ChannelHeader) msgprocessor.Classification {
	fake.classifyMsgMutex.Lock()
	ret, specificReturn := fake.classifyMsgReturnsOnCall[len(fake.classifyMsgArgsForCall)]
	fake.classifyMsgArgsForCall = append(fake.classifyMsgArgsForCall, struct {
		arg1 *common.ChannelHeader
	}{arg1})
	fake.recordInvocation("ClassifyMsg", []interface{}{arg1})
	fake.classifyMsgMutex.Unlock()
	if fake.ClassifyMsgStub != nil {
		return fake.ClassifyMsgStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.classifyMsgReturns
	return fakeReturns.result1
}
~~~

最后将频道头、配置信息、频道和错误信息返回给ProcessMessage函数并分别存储于临时变量chdr, isConfig, processor和err中，进行各种错误判断。如果上述步骤中均未出错，则调用ProcessNormalMsg函数将结果返回到configSeq和err中：

~~~
//orderer/common/broadcast/mock/channel_support.go

func (fake *ChannelSupport) ProcessNormalMsg(arg1 *common.Envelope) (uint64, error) {
	fake.processNormalMsgMutex.Lock()
	ret, specificReturn := fake.processNormalMsgReturnsOnCall[len(fake.processNormalMsgArgsForCall)]
	fake.processNormalMsgArgsForCall = append(fake.processNormalMsgArgsForCall, struct {
		arg1 *common.Envelope
	}{arg1})
	fake.recordInvocation("ProcessNormalMsg", []interface{}{arg1})
	fake.processNormalMsgMutex.Unlock()
	if fake.ProcessNormalMsgStub != nil {
		return fake.ProcessNormalMsgStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.processNormalMsgReturns
	return fakeReturns.result1, fakeReturns.result2
}
~~~

如果没有出错，则调用Order方法，在完成了复杂的验证工作后实现了一条消息的入队：

~~~
//orderer/common/broadcast/mock/channel_support.go

func (fake *ChannelSupport) Order(arg1 *common.Envelope, arg2 uint64) error {
	fake.orderMutex.Lock()
	ret, specificReturn := fake.orderReturnsOnCall[len(fake.orderArgsForCall)]
	fake.orderArgsForCall = append(fake.orderArgsForCall, struct {
		arg1 *common.Envelope
		arg2 uint64
	}{arg1, arg2})
	fake.recordInvocation("Order", []interface{}{arg1, arg2})
	fake.orderMutex.Unlock()
	if fake.OrderStub != nil {
		return fake.OrderStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.orderReturns
	return fakeReturns.result1
}
~~~

至此，ProcessMessage函数执行结束，排序服务节点生成区块，将一条消息加到链上的工作也已经完成。

以上就是Fabric交易从产生到记入账本的全过程。
