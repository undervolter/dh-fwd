# P2PDll.dll (SmartPSS Lite, x64, 2021-03-10) — internal function inventory

Extracted from DPrintLog string tables (.rdata): every logged function leaves
file.cpp + Dahua::Tou::Class::method + format string adjacent on disk.
IDA base in this table: 0x180000000. Find string -> xref -> function body.

## Modules (source files present in log strings)

  Address.cpp
  ClientFactory.cpp
  Common.cpp
  ComponentFactory.cpp
  DevicePasswordAuth.cpp
  DomainParse.cpp
  FifoBuffer.cpp
  File.cpp
  ICESession.cpp
  ICICEAgent.cpp
  LinkThroughClientImpl.cpp
  Md5.cpp
  MultiStunClient.cpp
  NatEventDriver.cpp
  OldUnknown.cpp
  P2PClient.cpp
  P2PDll.cpp
  P2PLinkThrough.cpp
  P2PLinkThroughClient.cpp
  P2PLinkThroughLocal.cpp
  P2PLinkThroughRelay.cpp
  P2PLinkThroughTcpRelay.cpp
  P2PMessageParser.cpp
  P2PSDKChannelClient.cpp
  Packet.cpp
  PacketManager.cpp
  PhonyTcp.cpp
  PhonyTcpReactor.cpp
  PhonyTcpTimer.cpp
  PhonyTcpTransport.cpp
  PrintLog.cpp
  ProxyChannel.cpp
  ProxyChannelClient.cpp
  ProxyClient.cpp
  ProxyClientCWrap.cpp
  ProxyClientConfig.cpp
  ProxyClientImpl.cpp
  ProxyP2PClient.cpp
  ProxyServerConfig.cpp
  ProxySession.cpp
  ProxyThreadPool.cpp
  Ptcp.cpp
  PtcpChannel.cpp
  PtcpChannelMng.cpp
  ReadWriteMutex.cpp
  ReceiverBuffer.cpp
  Semaphore.cpp
  Sha1cpp.cpp
  Socket.cpp
  StunClientImp.cpp
  StunClientLink.cpp
  StunMSG.cpp
  TcpRelayChannel.cpp
  Thread.cpp
  TimeOffset.cpp
  Timer.cpp
  TouReactorSelect.cpp
  UdpClient.cpp
  UdpSenderBuffer.cpp

## Named functions (name-string RVA = IDA address of the anchor)

 @Dahua::Tou::CPtcp::perform |rva=0x00132c17 ida=0x180132c17 
 Dahua::Component::CClientInstanceList::instance |rva=0x0013d908 ida=0x18013d908 
 Dahua::Component::Detail::CComponentHelper::getComponentFactory |rva=0x0013c780 ida=0x18013c780 
 Dahua::Component::IClientFactoryWrap::create |rva=0x0013d960 ida=0x18013d960 
 Dahua::Component::IClientFactoryWrap::createAndMake |rva=0x0013da08 ida=0x18013da08 
 Dahua::Infra::CThread::createThread |rva=0x0013b880 ida=0x18013b880 
 Dahua::Infra::CThread::destroyThread |rva=0x0013b970 ida=0x18013b970 
 Dahua::Infra::CThread::~CThread |rva=0x0013ba08 ida=0x18013ba08 
 Dahua::Infra::CTimer::stopAndWait |rva=0x0013e6f8 ida=0x18013e6f8 
 Dahua::Infra::CTimerManager::CTimerManager |rva=0x0013e758 ida=0x18013e758 
 Dahua::Infra::CTimerManager::instance |rva=0x0013e898 ida=0x18013e898 
 Dahua::Infra::ThreadManagerInternal::instance |rva=0x0013baa8 ida=0x18013baa8 
 Dahua::Infra::TimerManagerInternal::instance |rva=0x0013e678 ida=0x18013e678 
 Dahua::Memory::OldPacketInternal::create |rva=0x0013bbf0 ida=0x18013bbf0 
 Dahua::Memory::PacketManagerInternal::PacketManagerInternal |rva=0x0013d170 ida=0x18013d170 
 Dahua::Memory::PacketManagerInternal::instance |rva=0x0013d228 ida=0x18013d228 
 Dahua::NATTraver::Address::getLocalIP |rva=0x00134ac8 ida=0x180134ac8 
 Dahua::NATTraver::Address::getLocalIP |rva=0x00134b20 ida=0x180134b20 
 Dahua::NATTraver::Address::isIpv6Net |rva=0x00134b88 ida=0x180134b88 
 Dahua::NATTraver::Address::isIpv6Net |rva=0x00134be8 ida=0x180134be8 
 Dahua::NATTraver::Address::setIp |rva=0x00134c40 ida=0x180134c40 
 Dahua::NATTraver::Address::setIp |rva=0x00134ca8 ida=0x180134ca8 
 Dahua::NATTraver::Address::setIp |rva=0x00134d08 ida=0x180134d08 
 Dahua::NATTraver::CICEAgent::getOldFlowConfig |rva=0x00135d18 ida=0x180135d18 
 Dahua::NATTraver::CICEAgent::getSessionConfig |rva=0x00135ad8 ida=0x180135ad8 
 Dahua::NATTraver::CICEAgent::getSessionConfig |rva=0x00135b40 ida=0x180135b40 
 Dahua::NATTraver::CICEAgent::getSessionConfig |rva=0x00135bb0 ida=0x180135bb0 
 Dahua::NATTraver::CICEAgent::getSessionConfig |rva=0x00135c20 ida=0x180135c20 
 Dahua::NATTraver::CICEAgent::getSessionConfig |rva=0x00135c90 ida=0x180135c90 
 Dahua::NATTraver::CICEAgent::heartbeat |rva=0x00135f60 ida=0x180135f60 
 Dahua::NATTraver::CICEAgent::setConfig |rva=0x00135830 ida=0x180135830 
 Dahua::NATTraver::CICEAgent::setConfig |rva=0x001358b8 ida=0x1801358b8 
 Dahua::NATTraver::CICEAgent::setConfig |rva=0x00135940 ida=0x180135940 
 Dahua::NATTraver::CICEAgent::setConfig |rva=0x001359d0 ida=0x1801359d0 
 Dahua::NATTraver::CICEAgent::setConnInfoHandler |rva=0x00135a68 ida=0x180135a68 
 Dahua::NATTraver::CICEAgent::startConnectCheck |rva=0x00135d98 ida=0x180135d98 
 Dahua::NATTraver::CICEAgent::startConnectCheck |rva=0x00135e08 ida=0x180135e08 
 Dahua::NATTraver::CICEAgent::startConnectCheck |rva=0x00135e70 ida=0x180135e70 
 Dahua::NATTraver::CICEAgent::startConnectCheck |rva=0x00135ee8 ida=0x180135ee8 
 Dahua::NATTraver::CICEAgent::~CICEAgent |rva=0x00135788 ida=0x180135788 
 Dahua::NATTraver::CICESession::getConnInfo |rva=0x00139d48 ida=0x180139d48 
 Dahua::NATTraver::CICESession::getConnInfo |rva=0x00139db8 ida=0x180139db8 
 Dahua::NATTraver::CICESession::getConnInfo |rva=0x00139e38 ida=0x180139e38 
 Dahua::NATTraver::CICESession::onMessage |rva=0x00139eb0 ida=0x180139eb0 
 Dahua::NATTraver::CICESession::sendAckMessage |rva=0x0013a038 ida=0x18013a038 
 Dahua::NATTraver::CICESession::sendSynAckMessage |rva=0x00139fb0 ida=0x180139fb0 
 Dahua::NATTraver::CICESession::sendSynMessage |rva=0x00139f30 ida=0x180139f30 
 Dahua::NATTraver::CNATEventDriver::attach |rva=0x00138bc0 ida=0x180138bc0 
 Dahua::NATTraver::CNATEventDriverInstance::attach |rva=0x00138b08 ida=0x180138b08 
 Dahua::NATTraver::CSCLink::dealChangedAddress |rva=0x001392f8 ida=0x1801392f8 
 Dahua::NATTraver::CSCLink::dealMappedAddress |rva=0x001391d8 ida=0x1801391d8 
 Dahua::NATTraver::CSCLink::dealSouceAddress |rva=0x00139268 ida=0x180139268 
 Dahua::NATTraver::CSCLink::getLocalAddr |rva=0x00139380 ida=0x180139380 
 Dahua::NATTraver::CSCLink::sendContrAddrResponse |rva=0x00139518 ida=0x180139518 
 Dahua::NATTraver::CSCLink::sendContrRequest |rva=0x00139400 ida=0x180139400 
 Dahua::NATTraver::CSCLink::sendContrResponse |rva=0x00139488 ida=0x180139488 
 Dahua::NATTraver::CStunClient::heartbeat |rva=0x00137c50 ida=0x180137c50 
 Dahua::NATTraver::CStunClient::sendBindingRequest |rva=0x00137a88 ida=0x180137a88 
 Dahua::NATTraver::CStunClient::sendBindingRequest |rva=0x00137b20 ida=0x180137b20 
 Dahua::NATTraver::CStunClient::sendMessage |rva=0x00137bd0 ida=0x180137bd0 
 Dahua::NATTraver::CStunClient::setConfig |rva=0x00137990 ida=0x180137990 
 Dahua::NATTraver::CStunClient::setConfig |rva=0x00137a10 ida=0x180137a10 
 Dahua::NATTraver::CStunClient::~CStunClient |rva=0x001378e8 ida=0x1801378e8 
 Dahua::NATTraver::CStunMSG::createBindingResponse |rva=0x0013a250 ida=0x18013a250 
 Dahua::NATTraver::CStunMSG::createMsg |rva=0x0013a370 ida=0x18013a370 
 Dahua::NATTraver::CStunMSG::getConnId |rva=0x0013a4d8 ida=0x18013a4d8 
 Dahua::NATTraver::CStunMSG::getMessageId |rva=0x0013a1e0 ida=0x18013a1e0 
 Dahua::NATTraver::CStunMSG::getTurnPeer |rva=0x0013a468 ida=0x18013a468 
 Dahua::NATTraver::CStunMSG::printErrorInfo |rva=0x0013a3e0 ida=0x18013a3e0 
 Dahua::NATTraver::CStunMSG::toIOVec |rva=0x0013a170 ida=0x18013a170 
 Dahua::NATTraver::IICEAgent::generateID |rva=0x00135710 ida=0x180135710 
 Dahua::NATTraver::Socket::Socket |rva=0x00135060 ida=0x180135060 
 Dahua::NATTraver::Socket::connect |rva=0x001350d0 ida=0x1801350d0 
 Dahua::NATTraver::Socket::connect |rva=0x00135150 ida=0x180135150 
 Dahua::NATTraver::Socket::createSocket |rva=0x00135240 ida=0x180135240 
 Dahua::NATTraver::Socket::select |rva=0x001351c0 ida=0x1801351c0 
 Dahua::Tou::CDevicePasswordAuth::decryptLocalIpAddr |rva=0x00133138 ida=0x180133138 
 Dahua::Tou::CDevicePasswordAuth::encryptLocalIpAddr |rva=0x001330e8 ida=0x1801330e8 
 Dahua::Tou::CDomainParse::getDomainIP |rva=0x00127eb0 ida=0x180127eb0 
 Dahua::Tou::CFifoBuffer::consumeReadData |rva=0x0012db88 ida=0x18012db88 
 Dahua::Tou::CFifoBuffer::consumeWriteBuffer |rva=0x0012dbe8 ida=0x18012dbe8 
 Dahua::Tou::CFifoBuffer::getWriteRemaining |rva=0x0012da70 ida=0x18012da70 
 Dahua::Tou::CFifoBuffer::pop |rva=0x0012daf8 ida=0x18012daf8 
 Dahua::Tou::CFifoBuffer::read |rva=0x0012dad8 ida=0x18012dad8 
 Dahua::Tou::CFifoBuffer::readOffset |rva=0x0012db38 ida=0x18012db38 
 Dahua::Tou::CFifoBuffer::setCapacity |rva=0x0012d9c0 ida=0x18012d9c0 
 Dahua::Tou::CFifoBuffer::write |rva=0x0012db18 ida=0x18012db18 
 Dahua::Tou::CFifoBuffer::writeOffset |rva=0x0012db60 ida=0x18012db60 
 Dahua::Tou::CLinkThroughClientImpl::isPeerSupportLinkSwitchAndLocalP2P |rva=0x0012d480 ida=0x18012d480 
 Dahua::Tou::CLinkThroughClientImpl::onLinkPolicyNotify |rva=0x0012d8a0 ida=0x18012d8a0 
 Dahua::Tou::CLinkThroughClientImpl::onLinkThroughNotify |rva=0x0012d600 ida=0x18012d600 
 Dahua::Tou::CLinkThroughSingleThread::instance |rva=0x0012d7f8 ida=0x18012d7f8 
 Dahua::Tou::CLinkThroughSingleThread::stop |rva=0x0012d4e8 ida=0x18012d4e8 
 Dahua::Tou::CMultiStunClient::CMultiStunClient |rva=0x0012cac8 ida=0x18012cac8 
 Dahua::Tou::CMultiStunClient::calculateValueT |rva=0x0012cc20 ida=0x18012cc20 
 Dahua::Tou::CMultiStunClient::dealServerMessage |rva=0x0012cc88 ida=0x18012cc88 
 Dahua::Tou::CMultiStunClient::dealStunMessage |rva=0x0012cd10 ida=0x18012cd10 
 Dahua::Tou::CMultiStunClient::instance |rva=0x0012cb60 ida=0x18012cb60 
 Dahua::Tou::CMultiStunClient::onWaitNatInfo |rva=0x0012c7e0 ida=0x18012c7e0 
 Dahua::Tou::CMultiStunClient::stop |rva=0x0012c778 ida=0x18012c778 
 Dahua::Tou::CMultiStunClient::~CMultiStunClient |rva=0x0012ca10 ida=0x18012ca10 
 Dahua::Tou::CP2PClientImpl::getDeviceInfo |rva=0x0012e5f0 ida=0x18012e5f0 
 Dahua::Tou::CP2PClientImpl::getFromDevice |rva=0x0012ef30 ida=0x18012ef30 
 Dahua::Tou::CP2PClientImpl::getFromServer |rva=0x0012ed90 ida=0x18012ed90 
 Dahua::Tou::CP2PClientImpl::isDeviceOnline |rva=0x0012e940 ida=0x18012e940 
 Dahua::Tou::CP2PClientImpl::isServerOnline |rva=0x0012eba0 ida=0x18012eba0 
 Dahua::Tou::CP2PClientImpl::parseDeviceInfo |rva=0x0012eaf0 ida=0x18012eaf0 
 Dahua::Tou::CP2PClientImpl::sendInfoDeviceReq |rva=0x0012e748 ida=0x18012e748 
 Dahua::Tou::CP2PLinkThrough::getCandidateAddr |rva=0x001325c8 ida=0x1801325c8 
 Dahua::Tou::CP2PLinkThrough::onIce |rva=0x001327f8 ida=0x1801327f8 
 Dahua::Tou::CP2PLinkThrough::onStun |rva=0x001326f8 ida=0x1801326f8 
 Dahua::Tou::CP2PLinkThrough::setLocalValueT |rva=0x00132620 ida=0x180132620 
 Dahua::Tou::CP2PLinkThrough::setRemoteValueT |rva=0x00132668 ida=0x180132668 
 Dahua::Tou::CP2PLinkThrough::startIce |rva=0x001328b0 ida=0x1801328b0 
 Dahua::Tou::CP2PLinkThrough::startStun |rva=0x00132760 ida=0x180132760 
 Dahua::Tou::CP2PLinkThrough::~CP2PLinkThrough |rva=0x00132920 ida=0x180132920 
 Dahua::Tou::CP2PLinkThroughClient::enLocalAddr |rva=0x00132330 ida=0x180132330 
 Dahua::Tou::CP2PLinkThroughClient::heartbeat |rva=0x00132530 ida=0x180132530 
 Dahua::Tou::CP2PLinkThroughClient::onChannelStateIceWaitConfig |rva=0x00131da0 ida=0x180131da0 
 Dahua::Tou::CP2PLinkThroughClient::onChannelStateInvalid |rva=0x00131e50 ida=0x180131e50 
 Dahua::Tou::CP2PLinkThroughClient::onChannelStateStunSucess |rva=0x00132498 ida=0x180132498 
 Dahua::Tou::CP2PLinkThroughClient::onP2PRespError |rva=0x00132088 ida=0x180132088 
 Dahua::Tou::CP2PLinkThroughClient::onP2PResponse |rva=0x00132270 ida=0x180132270 
 Dahua::Tou::CP2PLinkThroughLocal::heartbeat |rva=0x00131600 ida=0x180131600 
 Dahua::Tou::CP2PLinkThroughLocal::onChannelInit |rva=0x00131578 ida=0x180131578 
 Dahua::Tou::CP2PLinkThroughLocal::onChannelWait |rva=0x001314a8 ida=0x1801314a8 
 Dahua::Tou::CP2PLinkThroughLocal::~CP2PLinkThroughLocal |rva=0x00131408 ida=0x180131408 
 Dahua::Tou::CP2PLinkThroughRelay::getCandidateAddr |rva=0x001304c8 ida=0x1801304c8 
 Dahua::Tou::CP2PLinkThroughRelay::heartbeat |rva=0x00131350 ida=0x180131350 
 Dahua::Tou::CP2PLinkThroughRelay::onBindSuccess |rva=0x00131218 ida=0x180131218 
 Dahua::Tou::CP2PLinkThroughRelay::onChannelInit |rva=0x001312c8 ida=0x1801312c8 
 Dahua::Tou::CP2PLinkThroughRelay::onGetAgentSucess |rva=0x00131098 ida=0x180131098 
 Dahua::Tou::CP2PLinkThroughRelay::onGetRelaySucess |rva=0x00131008 ida=0x180131008 
 Dahua::Tou::CP2PLinkThroughRelay::onICEWaitConfig |rva=0x00130718 ida=0x180130718 
 Dahua::Tou::CP2PLinkThroughRelay::onIce |rva=0x00130810 ida=0x180130810 
 Dahua::Tou::CP2PLinkThroughRelay::onRelayResponse |rva=0x00130ef0 ida=0x180130ef0 
 Dahua::Tou::CP2PLinkThroughRelay::onReponseRelayChannel |rva=0x00130bc8 ida=0x180130bc8 
 Dahua::Tou::CP2PLinkThroughRelay::onResponseGetRelay |rva=0x00130c90 ida=0x180130c90 
 Dahua::Tou::CP2PLinkThroughRelay::onResponseP2PChannel |rva=0x00130b28 ida=0x180130b28 
 Dahua::Tou::CP2PLinkThroughRelay::onResponseRelayAgent |rva=0x00130d88 ida=0x180130d88 
 Dahua::Tou::CP2PLinkThroughRelay::onResponseRelayStart |rva=0x00130a90 ida=0x180130a90 
 Dahua::Tou::CP2PLinkThroughRelay::onResponseUnbind |rva=0x00130560 ida=0x180130560 
 Dahua::Tou::CP2PLinkThroughRelay::onWaitAgentConfig |rva=0x00130630 ida=0x180130630 
 Dahua::Tou::CP2PLinkThroughRelay::onWaitRelayConfig |rva=0x001305c8 ida=0x1801305c8 
 Dahua::Tou::CP2PLinkThroughRelay::onWaitStartInfo |rva=0x001306a0 ida=0x1801306a0 
 Dahua::Tou::CP2PLinkThroughRelay::setRelayAgentInfo |rva=0x00130468 ida=0x180130468 
 Dahua::Tou::CP2PLinkThroughRelay::startIce |rva=0x00130958 ida=0x180130958 
 Dahua::Tou::CP2PLinkThroughRelay::~CP2PLinkThroughRelay |rva=0x00130e50 ida=0x180130e50 
 Dahua::Tou::CP2PLinkThroughTcpRelay::onChannelInit |rva=0x00131b18 ida=0x180131b18 
 Dahua::Tou::CP2PLinkThroughTcpRelay::onGetAgentSuccess |rva=0x00131858 ida=0x180131858 
 Dahua::Tou::CP2PLinkThroughTcpRelay::onWaitAgentBind |rva=0x00131a68 ida=0x180131a68 
 Dahua::Tou::CP2PLinkThroughTcpRelay::onWaitAgentConfig |rva=0x00131c10 ida=0x180131c10 
 Dahua::Tou::CP2PLinkThroughTcpRelay::onWaitConnectAgent |rva=0x00131928 ida=0x180131928 
 Dahua::Tou::CP2PLinkThroughTcpRelay::setTcpRelayAgentAddr |rva=0x001316a0 ida=0x1801316a0 
 Dahua::Tou::CP2PLinkThroughTcpRelay::~CP2PLinkThroughTcpRelay |rva=0x00131730 ida=0x180131730 
 Dahua::Tou::CP2PMessageParser::string2Addr |rva=0x00132ee0 ida=0x180132ee0 
 Dahua::Tou::CP2PSDKChannelClient::sendRequest |rva=0x00132cc8 ida=0x180132cc8 
 Dahua::Tou::CP2PSDKChannelClient::sendTcpRequest |rva=0x00132d38 ida=0x180132d38 
 Dahua::Tou::CPhonyTcp::applyOption |rva=0x00133a30 ida=0x180133a30 
 Dahua::Tou::CPhonyTcp::attemptSend |rva=0x00133f50 ida=0x180133f50 
 Dahua::Tou::CPhonyTcp::clock_check |rva=0x00133858 ida=0x180133858 
 Dahua::Tou::CPhonyTcp::closedown |rva=0x001338c0 ida=0x1801338c0 
 Dahua::Tou::CPhonyTcp::connect |rva=0x00134010 ida=0x180134010 
 Dahua::Tou::CPhonyTcp::getOption |rva=0x001337c0 ida=0x1801337c0 
 Dahua::Tou::CPhonyTcp::notifyClock |rva=0x00134130 ida=0x180134130 
 Dahua::Tou::CPhonyTcp::notifyPacket |rva=0x00134490 ida=0x180134490 
 Dahua::Tou::CPhonyTcp::packet |rva=0x00133cd0 ida=0x180133cd0 
 Dahua::Tou::CPhonyTcp::parse |rva=0x00134438 ida=0x180134438 
 Dahua::Tou::CPhonyTcp::parseOptions |rva=0x00134230 ida=0x180134230 
 Dahua::Tou::CPhonyTcp::process |rva=0x00134370 ida=0x180134370 
 Dahua::Tou::CPhonyTcp::processReceiver |rva=0x00133da8 ida=0x180133da8 
 Dahua::Tou::CPhonyTcp::processSender |rva=0x00133b60 ida=0x180133b60 
 Dahua::Tou::CPhonyTcp::queue |rva=0x00133e10 ida=0x180133e10 
 Dahua::Tou::CPhonyTcp::recv |rva=0x001341a0 ida=0x1801341a0 
 Dahua::Tou::CPhonyTcp::resizeReceiveBuffer |rva=0x00133950 ida=0x180133950 
 Dahua::Tou::CPhonyTcp::resizeSendBuffer |rva=0x00133908 ida=0x180133908 
 Dahua::Tou::CPhonyTcp::retransAckSegment |rva=0x00133f78 ida=0x180133f78 
 Dahua::Tou::CPhonyTcp::setOption |rva=0x00133980 ida=0x180133980 
 Dahua::Tou::CPhonyTcp::transmit |rva=0x00133e78 ida=0x180133e78 
 Dahua::Tou::CPhonyTcp::~CPhonyTcp |rva=0x00133c30 ida=0x180133c30 
 Dahua::Tou::CPhonyTcpReactor::instance |rva=0x0012de68 ida=0x18012de68 
 Dahua::Tou::CPhonyTcpReactor::stop |rva=0x0012dd80 ida=0x18012dd80 
 Dahua::Tou::CPhonyTcpTimer::attach |rva=0x00134618 ida=0x180134618 
 Dahua::Tou::CPhonyTcpTimer::instance |rva=0x001346f0 ida=0x1801346f0 
 Dahua::Tou::CPhonyTcpTimer::stop |rva=0x001344f8 ida=0x1801344f8 
 Dahua::Tou::CPhonyTcpTransport::CRecvTimer::recvData |rva=0x00133578 ida=0x180133578 
 Dahua::Tou::CPhonyTcpTransport::CRecvTimer::startTimer |rva=0x001335d8 ida=0x1801335d8 
 Dahua::Tou::CPhonyTcpTransport::CRecvTimer::stopTimer |rva=0x00133638 ida=0x180133638 
 Dahua::Tou::CPhonyTcpTransport::OnTcpClosed |rva=0x001333a0 ida=0x1801333a0 
 Dahua::Tou::CPhonyTcpTransport::bind |rva=0x001336f8 ida=0x1801336f8 
 Dahua::Tou::CPhonyTcpTransport::connect |rva=0x00133770 ida=0x180133770 
 Dahua::Tou::CPhonyTcpTransport::doConnect |rva=0x001334d8 ida=0x1801334d8 
 Dahua::Tou::CPhonyTcpTransport::getsockopt |rva=0x00133370 ida=0x180133370 
 Dahua::Tou::CPhonyTcpTransport::handleTimeout |rva=0x00133400 ida=0x180133400 
 Dahua::Tou::CPhonyTcpTransport::setsockopt |rva=0x00133320 ida=0x180133320 
 Dahua::Tou::CPortResource::get |rva=0x00128bb8 ida=0x180128bb8 
 Dahua::Tou::CPortResource::getFd |rva=0x00128af0 ida=0x180128af0 
 Dahua::Tou::CPortResource::getKey |rva=0x00128a78 ida=0x180128a78 
 Dahua::Tou::CPortResource::isKeyExist |rva=0x00128910 ida=0x180128910 
 Dahua::Tou::CProxyChannel::checkTouPacket |rva=0x0012a9f8 ida=0x18012a9f8 
 Dahua::Tou::CProxyChannel::isSessionData |rva=0x0012a958 ida=0x18012a958 
 Dahua::Tou::CProxyChannel::queryBuf |rva=0x0012aae8 ida=0x18012aae8 
 Dahua::Tou::CProxyChannel::sendAck |rva=0x0012ad38 ida=0x18012ad38 
 Dahua::Tou::CProxyChannel::sendData |rva=0x0012ab78 ida=0x18012ab78 
 Dahua::Tou::CProxyChannel::sendKeepAlive |rva=0x0012ac18 ida=0x18012ac18 
 Dahua::Tou::CProxyChannel::sendPause |rva=0x0012ac70 ida=0x18012ac70 
 Dahua::Tou::CProxyChannel::sendResume |rva=0x0012ad88 ida=0x18012ad88 
 Dahua::Tou::CProxyChannel::sendResumeSuccess |rva=0x0012add8 ida=0x18012add8 
 Dahua::Tou::CProxyChannel::sendSyn |rva=0x0012acc0 ida=0x18012acc0 
 Dahua::Tou::CProxyChannel::transferState |rva=0x0012aa28 ida=0x18012aa28 
 Dahua::Tou::CProxyChannel::writev |rva=0x0012abc8 ida=0x18012abc8 
 Dahua::Tou::CProxyChannel::~CProxyChannel |rva=0x0012ae80 ida=0x18012ae80 
 Dahua::Tou::CProxyChannelClient::CProxyChannelClient |rva=0x0012bab0 ida=0x18012bab0 
 Dahua::Tou::CProxyChannelClient::createTcpSession |rva=0x0012b838 ida=0x18012b838 
 Dahua::Tou::CProxyChannelClient::heartbeat |rva=0x0012bc10 ida=0x18012bc10 
 Dahua::Tou::CProxyChannelClient::isPeerSupportLinkSwitchAndLocalP2P |rva=0x0012afa0 ida=0x18012afa0 
 Dahua::Tou::CProxyChannelClient::notifyFirstP2PFinish |rva=0x0012b0c0 ida=0x18012b0c0 
 Dahua::Tou::CProxyChannelClient::onTouPacket |rva=0x0012b928 ida=0x18012b928 
 Dahua::Tou::CProxyChannelClient::procLinkSwitch |rva=0x0012b720 ida=0x18012b720 
 Dahua::Tou::CProxyChannelClient::procLinkSwitchException |rva=0x0012b5a0 ida=0x18012b5a0 
 Dahua::Tou::CProxyChannelClient::queryLinkState |rva=0x0012bb90 ida=0x18012bb90 
 Dahua::Tou::CProxyChannelClient::replaceLink |rva=0x0012b078 ida=0x18012b078 
 Dahua::Tou::CProxyChannelClient::reportTraversalInfo |rva=0x0012b308 ida=0x18012b308 
 Dahua::Tou::CProxyChannelClient::sendDataInSwitchChannel |rva=0x0012b158 ida=0x18012b158 
 Dahua::Tou::CProxyChannelClient::sendKeepAlive |rva=0x0012b298 ida=0x18012b298 
 Dahua::Tou::CProxyChannelClient::sendResume |rva=0x0012b1f0 ida=0x18012b1f0 
 Dahua::Tou::CProxyChannelClient::sessionCheck |rva=0x0012b9c0 ida=0x18012b9c0 
 Dahua::Tou::CProxyChannelClient::~CProxyChannelClient |rva=0x0012b388 ida=0x18012b388 
 Dahua::Tou::CProxyClient::CProxyClient |rva=0x00127d88 ida=0x180127d88 
 Dahua::Tou::CProxyClientConfig::getConfig |rva=0x00129ac0 ida=0x180129ac0 
 Dahua::Tou::CProxyClientImpl::CProxyClientImpl |rva=0x001294f8 ida=0x1801294f8 
 Dahua::Tou::CProxyClientImpl::addPort |rva=0x001295f0 ida=0x1801295f0 
 Dahua::Tou::CProxyClientImpl::createLocalPort |rva=0x001293b0 ida=0x1801293b0 
 Dahua::Tou::CProxyClientImpl::createTcpSession |rva=0x00128dc0 ida=0x180128dc0 
 Dahua::Tou::CProxyClientImpl::deletePort |rva=0x00129410 ida=0x180129410 
 Dahua::Tou::CProxyClientImpl::getState |rva=0x00128450 ida=0x180128450 
 Dahua::Tou::CProxyClientImpl::longTimeTaskDeal |rva=0x001291a8 ida=0x1801291a8 
 Dahua::Tou::CProxyClientImpl::onTcpAccept |rva=0x00128cb8 ida=0x180128cb8 
 Dahua::Tou::CProxyClientImpl::query |rva=0x00128a00 ida=0x180128a00 
 Dahua::Tou::CProxyClientImpl::queryLinkState |rva=0x00129090 ida=0x180129090 
 Dahua::Tou::CProxyClientImpl::release |rva=0x00129238 ida=0x180129238 
 Dahua::Tou::CProxyClientImpl::~CProxyClientImpl |rva=0x00128e70 ida=0x180128e70 
 Dahua::Tou::CProxyP2PClient::onEvent |rva=0x0012a4c0 ida=0x18012a4c0 
 Dahua::Tou::CProxyP2PClient::~CProxyP2PClient |rva=0x0012a7a8 ida=0x18012a7a8 
 Dahua::Tou::CProxyServerConfig::getConfig |rva=0x0012dd30 ida=0x18012dd30 
 Dahua::Tou::CProxySession::CProxySession |rva=0x0012c010 ida=0x18012c010 
 Dahua::Tou::CProxySession::connect |rva=0x0012bce8 ida=0x18012bce8 
 Dahua::Tou::CProxySession::heartbeat |rva=0x0012c268 ida=0x18012c268 
 Dahua::Tou::CProxySession::onData |rva=0x0012c3a8 ida=0x18012c3a8 
 Dahua::Tou::CProxySession::readTcp |rva=0x0012bf30 ida=0x18012bf30 
 Dahua::Tou::CProxySession::sendMessage |rva=0x0012bfc0 ida=0x18012bfc0 
 Dahua::Tou::CProxySession::sendNode |rva=0x0012bd98 ida=0x18012bd98 
 Dahua::Tou::CProxySession::setSessionFd |rva=0x0012c118 ida=0x18012c118 
 Dahua::Tou::CProxySession::~CProxySession |rva=0x0012c088 ida=0x18012c088 
 Dahua::Tou::CProxyThreadPool::instance |rva=0x0012e0d0 ida=0x18012e0d0 
 Dahua::Tou::CProxyThreadPool::stop |rva=0x0012ded0 ida=0x18012ded0 
 Dahua::Tou::CPtcp::~CPtcp |rva=0x00132be0 ida=0x180132be0 
 Dahua::Tou::CPtcpChannel::connect |rva=0x0012f2b0 ida=0x18012f2b0 
 Dahua::Tou::CPtcpChannel::heartbeat |rva=0x0012f368 ida=0x18012f368 
 Dahua::Tou::CPtcpChannel::longTimeTaskDeal |rva=0x0012f068 ida=0x18012f068 
 Dahua::Tou::CPtcpChannel::onClose |rva=0x0012f1f0 ida=0x18012f1f0 
 Dahua::Tou::CPtcpChannel::onConnect |rva=0x0012f138 ida=0x18012f138 
 Dahua::Tou::CPtcpChannel::onException |rva=0x0012f190 ida=0x18012f190 
 Dahua::Tou::CPtcpChannel::stopRecvTimer |rva=0x0012f3e0 ida=0x18012f3e0 
 Dahua::Tou::CPtcpChannel::~CPtcpChannel |rva=0x0012f4d8 ida=0x18012f4d8 
 Dahua::Tou::CPtcpChannelMng::create |rva=0x0012f710 ida=0x18012f710 
 Dahua::Tou::CPtcpChannelMng::createId |rva=0x0012f540 ida=0x18012f540 
 Dahua::Tou::CPtcpChannelMng::destroy |rva=0x0012f6a0 ida=0x18012f6a0 
 Dahua::Tou::CReceiverBuffer::read |rva=0x0012e158 ida=0x18012e158 
 Dahua::Tou::CReceiverBuffer::readOffsetLocked |rva=0x0012e270 ida=0x18012e270 
 Dahua::Tou::CReceiverBuffer::writeOffsetLocked |rva=0x0012e358 ida=0x18012e358 
 Dahua::Tou::CTcpRelayChannel::createSessionId |rva=0x00129c30 ida=0x180129c30 
 Dahua::Tou::CTcpRelayChannel::createTcpSession |rva=0x0012a0a0 ida=0x18012a0a0 
 Dahua::Tou::CTcpRelayChannel::heartbeat |rva=0x0012a398 ida=0x18012a398 
 Dahua::Tou::CTcpRelayChannel::longTimeTaskDeal |rva=0x00129fe8 ida=0x180129fe8 
 Dahua::Tou::CTcpRelayChannel::onRead |rva=0x0012a410 ida=0x18012a410 
 Dahua::Tou::CTcpRelayChannel::onTouPacket |rva=0x0012a170 ida=0x18012a170 
 Dahua::Tou::CTcpRelayChannel::parseTouPacket |rva=0x0012a328 ida=0x18012a328 
 Dahua::Tou::CTcpRelayChannel::sendAck |rva=0x00129e78 ida=0x180129e78 
 Dahua::Tou::CTcpRelayChannel::sendBufferMessage |rva=0x00129cf0 ida=0x180129cf0 
 Dahua::Tou::CTcpRelayChannel::sendData |rva=0x00129d60 ida=0x180129d60 
 Dahua::Tou::CTcpRelayChannel::sendKeepAlive |rva=0x00129ec8 ida=0x180129ec8 
 Dahua::Tou::CTcpRelayChannel::sendSyn |rva=0x00129e08 ida=0x180129e08 
 Dahua::Tou::CTcpRelayChannel::sessionCheck |rva=0x0012a240 ida=0x18012a240 
 Dahua::Tou::CTimeOffset::updateOffset |rva=0x001303c0 ida=0x1801303c0 
 Dahua::Tou::CUdpClientSingleThread::instance |rva=0x00132b10 ida=0x180132b10 
 Dahua::Tou::CUdpClientSingleThread::stop |rva=0x001329f0 ida=0x1801329f0 
 Dahua::Tou::CUdpSendBuffer::consumeReadData |rva=0x001348a8 ida=0x1801348a8 
 Dahua::Tou::CUdpSendBuffer::readOffsetLocked |rva=0x00134808 ida=0x180134808 
 Dahua::Tou::CUdpSendBuffer::writeOffsetLocked |rva=0x00134960 ida=0x180134960 
 Dahua::Tou::HttpQuery |rva=0x0012d378 ida=0x18012d378 
 Dahua::Tou::IsValidSockfd |rva=0x00133278 ida=0x180133278 
 Dahua::Tou::ReactorSelect::dispatch |rva=0x0013a8e0 ida=0x18013a8e0 
 Dahua::Tou::ReactorSelect::registFd |rva=0x0013a710 ida=0x18013a710 
 Dahua::Tou::ReactorSelect::registFd |rva=0x0013a780 ida=0x18013a780 
 Dahua::Tou::ReactorSelect::unregistFd |rva=0x0013a7f8 ida=0x18013a7f8 
 Dahua::Tou::ReactorSelect::unregistFd |rva=0x0013a870 ida=0x18013a870 
 Dahua::Tou::aesOfb265Encrypt2Str |rva=0x0012cec0 ida=0x18012cec0 
 Dahua::Tou::aesOfb265StrDecrypt |rva=0x0012cf40 ida=0x18012cf40 
 Dahua::Tou::kdf256 |rva=0x0012ce40 ida=0x18012ce40 
 Dahua::Tou::onXmlParse |rva=0x0012d1f8 ida=0x18012d1f8 
 Dahua::Tou::verstr2num |rva=0x0012d260 ida=0x18012d260 
 Dahua::Utils::CMd5::hex |rva=0x0013bf60 ida=0x18013bf60 
 Dahua::Utils::CSha1::final |rva=0x0013bfb8 ida=0x18013bfb8 
 __cdecl Dahua::Component::IClientFactoryWrap::IClientFactoryWrap(class Dahua::Component::IFactoryUnknown *) |rva=0x0013d460 ida=0x18013d460 
 __cdecl Dahua::Infra::CReadWriteMutex::CReadWriteMutex(void) |rva=0x0013bdc0 ida=0x18013bdc0 
 __cdecl Dahua::Infra::CSemaphore::CSemaphore(int) |rva=0x0013ce38 ida=0x18013ce38 
 bool __cdecl Dahua::Component::clientIsBroken(class Dahua::Component::IClient *) |rva=0x0013c520 ida=0x18013c520 
 bool __cdecl Dahua::Component::clientIsCreated(class Dahua::Component::IClient *) |rva=0x0013c460 ida=0x18013c460 
 bool __cdecl Dahua::Component::clientIsIdle(class Dahua::Component::IClient *) |rva=0x0013d3a0 ida=0x18013d3a0 
 bool __cdecl Dahua::Component::clientIsLogined(class Dahua::Component::IClient *) |rva=0x0013c4c0 ida=0x18013c4c0 
 bool __cdecl Dahua::Component::clientIsSameAs(class Dahua::Component::IClient *,const struct Dahua::Component::ClassID &,const struct Dahua::Component::ServerInfo &) |rva=0x0013d2f0 ida=0x18013d2f0 
 bool __cdecl Dahua::Component::clientLogin(class Dahua::Component::IClient *) |rva=0x0013c360 ida=0x18013c360 
 bool __cdecl Dahua::Component::clientUpdateBroken(class Dahua::Component::IClient *) |rva=0x0013c400 ida=0x18013c400 
 bool __cdecl Dahua::Component::destroyComponent(class Dahua::Component::IUnknown *,const char *,bool) |rva=0x0013c160 ida=0x18013c160 
 bool __cdecl Dahua::Infra::CThread::createThread(void) |rva=0x0013b820 ida=0x18013b820 
 int __cdecl Dahua::Component::CClientInstanceList::releaseClientInstance(class Dahua::Component::IClient *) |rva=0x0013d730 ida=0x18013d730 
 int __cdecl Dahua::Component::ClientFactory::releaseClientObject(class Dahua::Component::IClient *) |rva=0x0013da40 ida=0x18013da40 
 int __cdecl Dahua::Component::decreaseRefCount(class Dahua::Component::IUnknown *) |rva=0x0013bff0 ida=0x18013bff0 
 int __cdecl Dahua::Infra::CSemaphore::pend(void) |rva=0x0013ce90 ida=0x18013ce90 
 int __cdecl Dahua::Infra::CSemaphore::tryPend(void) |rva=0x0013cec8 ida=0x18013cec8 
 long __cdecl Dahua::Component::clientGetAndMarkUsing(class Dahua::Component::IClient *) |rva=0x0013d3f0 ida=0x18013d3f0 
 void *__cdecl Dahua::Infra::FileDefaultOpt::fopen(const char *,const char *) |rva=0x0013e4e0 ida=0x18013e4e0 
 void __cdecl Dahua::Component::CClientInstanceList::removeIdleClientInstance(unsigned long) |rva=0x0013d820 ida=0x18013d820 
 void __cdecl Dahua::Component::clientCreateInternal(class Dahua::Component::IClient *,const struct Dahua::Component::ClassID &,const struct Dahua::Component::ServerInfo &,bool) |rva=0x0013d5f0 ida=0x18013d5f0 
 void __cdecl Dahua::Infra::TimerManagerInternal::threadProc(void) |rva=0x0013e7f0 ida=0x18013e7f0 
 void __cdecl Dahua::Memory::OldPacketInternal::destroy(void) |rva=0x0013bcc8 ida=0x18013bcc8 
 void __cdecl Dahua::Memory::PacketManagerInternal::Pool_Free(void *) |rva=0x0013cff0 ida=0x18013cff0 
