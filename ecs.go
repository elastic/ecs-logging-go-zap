// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package ecszap

// Do not manually change this file, as it is generated.
// If you want to update the file, run `make update-ecs`

import (
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Version is the current ECS version available in the ecs package.
const Version = "1.5.0"

const (
	AgentTypeKey = "agent.type"

	AgentEphemeralIDKey = "agent.ephemeral_id"

	AgentVersionKey = "agent.version"

	AgentNameKey = "agent.name"

	AgentIDKey = "agent.id"

	AsNumberKey = "as.number"

	AsOrganizationNameKey = "as.organization.name"

	ClientIPKey = "client.ip"

	ClientAddressKey = "client.address"

	ClientTopLevelDomainKey = "client.top_level_domain"

	ClientBytesKey = "client.bytes"

	ClientRegisteredDomainKey = "client.registered_domain"

	ClientPacketsKey = "client.packets"

	ClientPortKey = "client.port"

	ClientDomainKey = "client.domain"

	ClientMACKey = "client.mac"

	ClientAsNumberKey = "client.as.number"

	ClientAsOrganizationNameKey = "client.as.organization.name"

	ClientGeoContinentNameKey = "client.geo.continent_name"

	ClientGeoNameKey = "client.geo.name"

	ClientGeoRegionNameKey = "client.geo.region_name"

	ClientGeoLocationKey = "client.geo.location"

	ClientGeoCountryIsoCodeKey = "client.geo.country_iso_code"

	ClientGeoRegionIsoCodeKey = "client.geo.region_iso_code"

	ClientGeoCityNameKey = "client.geo.city_name"

	ClientGeoCountryNameKey = "client.geo.country_name"

	ClientNatPortKey = "client.nat.port"

	ClientNatIPKey = "client.nat.ip"

	ClientUserDomainKey = "client.user.domain"

	ClientUserFullNameKey = "client.user.full_name"

	ClientUserNameKey = "client.user.name"

	ClientUserHashKey = "client.user.hash"

	ClientUserEmailKey = "client.user.email"

	ClientUserIDKey = "client.user.id"

	ClientUserGroupNameKey = "client.user.group.name"

	ClientUserGroupIDKey = "client.user.group.id"

	ClientUserGroupDomainKey = "client.user.group.domain"

	CloudRegionKey = "cloud.region"

	CloudAvailabilityZoneKey = "cloud.availability_zone"

	CloudProviderKey = "cloud.provider"

	CloudAccountIDKey = "cloud.account.id"

	CloudInstanceIDKey = "cloud.instance.id"

	CloudInstanceNameKey = "cloud.instance.name"

	CloudMachineTypeKey = "cloud.machine.type"

	CodeSignatureValidKey = "code_signature.valid"

	CodeSignatureTrustedKey = "code_signature.trusted"

	CodeSignatureExistsKey = "code_signature.exists"

	CodeSignatureSubjectNameKey = "code_signature.subject_name"

	CodeSignatureStatusKey = "code_signature.status"

	ContainerIDKey = "container.id"

	ContainerLabelsKey = "container.labels"

	ContainerRuntimeKey = "container.runtime"

	ContainerNameKey = "container.name"

	ContainerImageNameKey = "container.image.name"

	ContainerImageTagKey = "container.image.tag"

	DestinationDomainKey = "destination.domain"

	DestinationIPKey = "destination.ip"

	DestinationMACKey = "destination.mac"

	DestinationPacketsKey = "destination.packets"

	DestinationRegisteredDomainKey = "destination.registered_domain"

	DestinationAddressKey = "destination.address"

	DestinationPortKey = "destination.port"

	DestinationTopLevelDomainKey = "destination.top_level_domain"

	DestinationBytesKey = "destination.bytes"

	DestinationAsNumberKey = "destination.as.number"

	DestinationAsOrganizationNameKey = "destination.as.organization.name"

	DestinationGeoCountryNameKey = "destination.geo.country_name"

	DestinationGeoLocationKey = "destination.geo.location"

	DestinationGeoRegionIsoCodeKey = "destination.geo.region_iso_code"

	DestinationGeoContinentNameKey = "destination.geo.continent_name"

	DestinationGeoCountryIsoCodeKey = "destination.geo.country_iso_code"

	DestinationGeoCityNameKey = "destination.geo.city_name"

	DestinationGeoNameKey = "destination.geo.name"

	DestinationGeoRegionNameKey = "destination.geo.region_name"

	DestinationNatPortKey = "destination.nat.port"

	DestinationNatIPKey = "destination.nat.ip"

	DestinationUserDomainKey = "destination.user.domain"

	DestinationUserIDKey = "destination.user.id"

	DestinationUserHashKey = "destination.user.hash"

	DestinationUserFullNameKey = "destination.user.full_name"

	DestinationUserNameKey = "destination.user.name"

	DestinationUserEmailKey = "destination.user.email"

	DestinationUserGroupDomainKey = "destination.user.group.domain"

	DestinationUserGroupIDKey = "destination.user.group.id"

	DestinationUserGroupNameKey = "destination.user.group.name"

	DllNameKey = "dll.name"

	DllPathKey = "dll.path"

	DllCodeSignatureExistsKey = "dll.code_signature.exists"

	DllCodeSignatureValidKey = "dll.code_signature.valid"

	DllCodeSignatureSubjectNameKey = "dll.code_signature.subject_name"

	DllCodeSignatureTrustedKey = "dll.code_signature.trusted"

	DllCodeSignatureStatusKey = "dll.code_signature.status"

	DllHashMd5Key = "dll.hash.md5"

	DllHashSha256Key = "dll.hash.sha256"

	DllHashSha1Key = "dll.hash.sha1"

	DllHashSha512Key = "dll.hash.sha512"

	DllPeDescriptionKey = "dll.pe.description"

	DllPeProductKey = "dll.pe.product"

	DllPeOriginalFileNameKey = "dll.pe.original_file_name"

	DllPeCompanyKey = "dll.pe.company"

	DllPeFileVersionKey = "dll.pe.file_version"

	DNSIDKey = "dns.id"

	DNSAnswersKey = "dns.answers"

	DNSResponseCodeKey = "dns.response_code"

	DNSOpCodeKey = "dns.op_code"

	DNSResolvedIPKey = "dns.resolved_ip"

	DNSTypeKey = "dns.type"

	DNSHeaderFlagsKey = "dns.header_flags"

	DNSAnswersClassKey = "dns.answers.class"

	DNSAnswersDataKey = "dns.answers.data"

	DNSAnswersNameKey = "dns.answers.name"

	DNSAnswersTypeKey = "dns.answers.type"

	DNSAnswersTTLKey = "dns.answers.ttl"

	DNSQuestionTopLevelDomainKey = "dns.question.top_level_domain"

	DNSQuestionTypeKey = "dns.question.type"

	DNSQuestionNameKey = "dns.question.name"

	DNSQuestionRegisteredDomainKey = "dns.question.registered_domain"

	DNSQuestionSubdomainKey = "dns.question.subdomain"

	DNSQuestionClassKey = "dns.question.class"

	ECSVersionKey = "ecs.version"

	ErrorIDKey = "error.id"

	ErrorStackTraceKey = "error.stack_trace"

	ErrorTypeKey = "error.type"

	ErrorMessageKey = "error.message"

	ErrorCodeKey = "error.code"

	EventKindKey = "event.kind"

	EventIDKey = "event.id"

	EventCodeKey = "event.code"

	EventModuleKey = "event.module"

	EventOriginalKey = "event.original"

	EventRiskScoreKey = "event.risk_score"

	EventIngestedKey = "event.ingested"

	EventDurationKey = "event.duration"

	EventCategoryKey = "event.category"

	EventSequenceKey = "event.sequence"

	EventHashKey = "event.hash"

	EventActionKey = "event.action"

	EventCreatedKey = "event.created"

	EventStartKey = "event.start"

	EventURLKey = "event.url"

	EventProviderKey = "event.provider"

	EventEndKey = "event.end"

	EventRiskScoreNormKey = "event.risk_score_norm"

	EventTypeKey = "event.type"

	EventTimezoneKey = "event.timezone"

	EventSeverityKey = "event.severity"

	EventOutcomeKey = "event.outcome"

	EventReferenceKey = "event.reference"

	EventDatasetKey = "event.dataset"

	FileCreatedKey = "file.created"

	FileMimeTypeKey = "file.mime_type"

	FileGidKey = "file.gid"

	FileCtimeKey = "file.ctime"

	FileDirectoryKey = "file.directory"

	FileNameKey = "file.name"

	FileUIDKey = "file.uid"

	FileMtimeKey = "file.mtime"

	FileGroupKey = "file.group"

	FileDriveLetterKey = "file.drive_letter"

	FilePathKey = "file.path"

	FileDeviceKey = "file.device"

	FileExtensionKey = "file.extension"

	FileSizeKey = "file.size"

	FileOwnerKey = "file.owner"

	FileTypeKey = "file.type"

	FileAttributesKey = "file.attributes"

	FileAccessedKey = "file.accessed"

	FileTargetPathKey = "file.target_path"

	FileModeKey = "file.mode"

	FileInodeKey = "file.inode"

	FileCodeSignatureSubjectNameKey = "file.code_signature.subject_name"

	FileCodeSignatureStatusKey = "file.code_signature.status"

	FileCodeSignatureExistsKey = "file.code_signature.exists"

	FileCodeSignatureTrustedKey = "file.code_signature.trusted"

	FileCodeSignatureValidKey = "file.code_signature.valid"

	FileHashSha256Key = "file.hash.sha256"

	FileHashSha1Key = "file.hash.sha1"

	FileHashMd5Key = "file.hash.md5"

	FileHashSha512Key = "file.hash.sha512"

	FilePeOriginalFileNameKey = "file.pe.original_file_name"

	FilePeFileVersionKey = "file.pe.file_version"

	FilePeProductKey = "file.pe.product"

	FilePeCompanyKey = "file.pe.company"

	FilePeDescriptionKey = "file.pe.description"

	GeoContinentNameKey = "geo.continent_name"

	GeoCountryNameKey = "geo.country_name"

	GeoNameKey = "geo.name"

	GeoLocationKey = "geo.location"

	GeoRegionNameKey = "geo.region_name"

	GeoRegionIsoCodeKey = "geo.region_iso_code"

	GeoCountryIsoCodeKey = "geo.country_iso_code"

	GeoCityNameKey = "geo.city_name"

	GroupIDKey = "group.id"

	GroupDomainKey = "group.domain"

	GroupNameKey = "group.name"

	HashSha256Key = "hash.sha256"

	HashSha512Key = "hash.sha512"

	HashMd5Key = "hash.md5"

	HashSha1Key = "hash.sha1"

	HostArchitectureKey = "host.architecture"

	HostDomainKey = "host.domain"

	HostIDKey = "host.id"

	HostNameKey = "host.name"

	HostIPKey = "host.ip"

	HostHostnameKey = "host.hostname"

	HostMACKey = "host.mac"

	HostTypeKey = "host.type"

	HostUptimeKey = "host.uptime"

	HostGeoCityNameKey = "host.geo.city_name"

	HostGeoLocationKey = "host.geo.location"

	HostGeoCountryNameKey = "host.geo.country_name"

	HostGeoRegionNameKey = "host.geo.region_name"

	HostGeoCountryIsoCodeKey = "host.geo.country_iso_code"

	HostGeoNameKey = "host.geo.name"

	HostGeoContinentNameKey = "host.geo.continent_name"

	HostGeoRegionIsoCodeKey = "host.geo.region_iso_code"

	HostOSPlatformKey = "host.os.platform"

	HostOSKernelKey = "host.os.kernel"

	HostOSFullKey = "host.os.full"

	HostOSVersionKey = "host.os.version"

	HostOSNameKey = "host.os.name"

	HostOSFamilyKey = "host.os.family"

	HostUserNameKey = "host.user.name"

	HostUserHashKey = "host.user.hash"

	HostUserEmailKey = "host.user.email"

	HostUserFullNameKey = "host.user.full_name"

	HostUserDomainKey = "host.user.domain"

	HostUserIDKey = "host.user.id"

	HostUserGroupDomainKey = "host.user.group.domain"

	HostUserGroupNameKey = "host.user.group.name"

	HostUserGroupIDKey = "host.user.group.id"

	HTTPVersionKey = "http.version"

	HTTPRequestReferrerKey = "http.request.referrer"

	HTTPRequestBytesKey = "http.request.bytes"

	HTTPRequestMethodKey = "http.request.method"

	HTTPRequestBodyContentKey = "http.request.body.content"

	HTTPRequestBodyBytesKey = "http.request.body.bytes"

	HTTPResponseStatusCodeKey = "http.response.status_code"

	HTTPResponseBytesKey = "http.response.bytes"

	HTTPResponseBodyBytesKey = "http.response.body.bytes"

	HTTPResponseBodyContentKey = "http.response.body.content"

	InterfaceAliasKey = "interface.alias"

	InterfaceNameKey = "interface.name"

	InterfaceIDKey = "interface.id"

	LogLevelKey = "log.level"

	LogLoggerKey = "log.logger"

	LogSyslogKey = "log.syslog"

	LogOriginalKey = "log.original"

	LogOriginFunctionKey = "log.origin.function"

	LogOriginFileNameKey = "log.origin.file.name"

	LogOriginFileLineKey = "log.origin.file.line"

	LogSyslogPriorityKey = "log.syslog.priority"

	LogSyslogFacilityNameKey = "log.syslog.facility.name"

	LogSyslogFacilityCodeKey = "log.syslog.facility.code"

	LogSyslogSeverityCodeKey = "log.syslog.severity.code"

	LogSyslogSeverityNameKey = "log.syslog.severity.name"

	NetworkBytesKey = "network.bytes"

	NetworkApplicationKey = "network.application"

	NetworkTransportKey = "network.transport"

	NetworkPacketsKey = "network.packets"

	NetworkCommunityIDKey = "network.community_id"

	NetworkProtocolKey = "network.protocol"

	NetworkIANANumberKey = "network.iana_number"

	NetworkDirectionKey = "network.direction"

	NetworkInnerKey = "network.inner"

	NetworkTypeKey = "network.type"

	NetworkForwardedIPKey = "network.forwarded_ip"

	NetworkNameKey = "network.name"

	NetworkInnerVlanIDKey = "network.inner.vlan.id"

	NetworkInnerVlanNameKey = "network.inner.vlan.name"

	NetworkVlanNameKey = "network.vlan.name"

	NetworkVlanIDKey = "network.vlan.id"

	ObserverIPKey = "observer.ip"

	ObserverEgressKey = "observer.egress"

	ObserverTypeKey = "observer.type"

	ObserverMACKey = "observer.mac"

	ObserverHostnameKey = "observer.hostname"

	ObserverSerialNumberKey = "observer.serial_number"

	ObserverProductKey = "observer.product"

	ObserverIngressKey = "observer.ingress"

	ObserverNameKey = "observer.name"

	ObserverVendorKey = "observer.vendor"

	ObserverVersionKey = "observer.version"

	ObserverEgressZoneKey = "observer.egress.zone"

	ObserverEgressInterfaceAliasKey = "observer.egress.interface.alias"

	ObserverEgressInterfaceNameKey = "observer.egress.interface.name"

	ObserverEgressInterfaceIDKey = "observer.egress.interface.id"

	ObserverEgressVlanIDKey = "observer.egress.vlan.id"

	ObserverEgressVlanNameKey = "observer.egress.vlan.name"

	ObserverGeoRegionNameKey = "observer.geo.region_name"

	ObserverGeoNameKey = "observer.geo.name"

	ObserverGeoContinentNameKey = "observer.geo.continent_name"

	ObserverGeoLocationKey = "observer.geo.location"

	ObserverGeoCountryIsoCodeKey = "observer.geo.country_iso_code"

	ObserverGeoRegionIsoCodeKey = "observer.geo.region_iso_code"

	ObserverGeoCountryNameKey = "observer.geo.country_name"

	ObserverGeoCityNameKey = "observer.geo.city_name"

	ObserverIngressZoneKey = "observer.ingress.zone"

	ObserverIngressInterfaceIDKey = "observer.ingress.interface.id"

	ObserverIngressInterfaceAliasKey = "observer.ingress.interface.alias"

	ObserverIngressInterfaceNameKey = "observer.ingress.interface.name"

	ObserverIngressVlanNameKey = "observer.ingress.vlan.name"

	ObserverIngressVlanIDKey = "observer.ingress.vlan.id"

	ObserverOSFamilyKey = "observer.os.family"

	ObserverOSNameKey = "observer.os.name"

	ObserverOSVersionKey = "observer.os.version"

	ObserverOSPlatformKey = "observer.os.platform"

	ObserverOSFullKey = "observer.os.full"

	ObserverOSKernelKey = "observer.os.kernel"

	OrganizationIDKey = "organization.id"

	OrganizationNameKey = "organization.name"

	OSPlatformKey = "os.platform"

	OSNameKey = "os.name"

	OSVersionKey = "os.version"

	OSFamilyKey = "os.family"

	OSFullKey = "os.full"

	OSKernelKey = "os.kernel"

	PackageLicenseKey = "package.license"

	PackageVersionKey = "package.version"

	PackageChecksumKey = "package.checksum"

	PackageSizeKey = "package.size"

	PackageNameKey = "package.name"

	PackageReferenceKey = "package.reference"

	PackageTypeKey = "package.type"

	PackagePathKey = "package.path"

	PackageInstalledKey = "package.installed"

	PackageBuildVersionKey = "package.build_version"

	PackageDescriptionKey = "package.description"

	PackageInstallScopeKey = "package.install_scope"

	PackageArchitectureKey = "package.architecture"

	PeFileVersionKey = "pe.file_version"

	PeDescriptionKey = "pe.description"

	PeCompanyKey = "pe.company"

	PeOriginalFileNameKey = "pe.original_file_name"

	PeProductKey = "pe.product"

	ProcessWorkingDirectoryKey = "process.working_directory"

	ProcessPPIDKey = "process.ppid"

	ProcessPgidKey = "process.pgid"

	ProcessEntityIDKey = "process.entity_id"

	ProcessArgsKey = "process.args"

	ProcessCommandLineKey = "process.command_line"

	ProcessUptimeKey = "process.uptime"

	ProcessStartKey = "process.start"

	ProcessExecutableKey = "process.executable"

	ProcessArgsCountKey = "process.args_count"

	ProcessTitleKey = "process.title"

	ProcessNameKey = "process.name"

	ProcessPIDKey = "process.pid"

	ProcessExitCodeKey = "process.exit_code"

	ProcessCodeSignatureValidKey = "process.code_signature.valid"

	ProcessCodeSignatureStatusKey = "process.code_signature.status"

	ProcessCodeSignatureTrustedKey = "process.code_signature.trusted"

	ProcessCodeSignatureExistsKey = "process.code_signature.exists"

	ProcessCodeSignatureSubjectNameKey = "process.code_signature.subject_name"

	ProcessHashSha512Key = "process.hash.sha512"

	ProcessHashSha256Key = "process.hash.sha256"

	ProcessHashMd5Key = "process.hash.md5"

	ProcessHashSha1Key = "process.hash.sha1"

	ProcessParentEntityIDKey = "process.parent.entity_id"

	ProcessParentExitCodeKey = "process.parent.exit_code"

	ProcessParentUptimeKey = "process.parent.uptime"

	ProcessParentTitleKey = "process.parent.title"

	ProcessParentStartKey = "process.parent.start"

	ProcessParentArgsKey = "process.parent.args"

	ProcessParentArgsCountKey = "process.parent.args_count"

	ProcessParentPgidKey = "process.parent.pgid"

	ProcessParentPPIDKey = "process.parent.ppid"

	ProcessParentCommandLineKey = "process.parent.command_line"

	ProcessParentNameKey = "process.parent.name"

	ProcessParentExecutableKey = "process.parent.executable"

	ProcessParentPIDKey = "process.parent.pid"

	ProcessParentWorkingDirectoryKey = "process.parent.working_directory"

	ProcessParentCodeSignatureExistsKey = "process.parent.code_signature.exists"

	ProcessParentCodeSignatureTrustedKey = "process.parent.code_signature.trusted"

	ProcessParentCodeSignatureStatusKey = "process.parent.code_signature.status"

	ProcessParentCodeSignatureSubjectNameKey = "process.parent.code_signature.subject_name"

	ProcessParentCodeSignatureValidKey = "process.parent.code_signature.valid"

	ProcessParentHashSha256Key = "process.parent.hash.sha256"

	ProcessParentHashSha1Key = "process.parent.hash.sha1"

	ProcessParentHashMd5Key = "process.parent.hash.md5"

	ProcessParentHashSha512Key = "process.parent.hash.sha512"

	ProcessParentThreadIDKey = "process.parent.thread.id"

	ProcessParentThreadNameKey = "process.parent.thread.name"

	ProcessPeOriginalFileNameKey = "process.pe.original_file_name"

	ProcessPeDescriptionKey = "process.pe.description"

	ProcessPeFileVersionKey = "process.pe.file_version"

	ProcessPeProductKey = "process.pe.product"

	ProcessPeCompanyKey = "process.pe.company"

	ProcessThreadNameKey = "process.thread.name"

	ProcessThreadIDKey = "process.thread.id"

	RegistryPathKey = "registry.path"

	RegistryValueKey = "registry.value"

	RegistryKeyKey = "registry.key"

	RegistryHiveKey = "registry.hive"

	RegistryDataStringsKey = "registry.data.strings"

	RegistryDataTypeKey = "registry.data.type"

	RegistryDataBytesKey = "registry.data.bytes"

	RelatedHashKey = "related.hash"

	RelatedUserKey = "related.user"

	RelatedIPKey = "related.ip"

	RuleAuthorKey = "rule.author"

	RuleReferenceKey = "rule.reference"

	RuleLicenseKey = "rule.license"

	RuleUUIDKey = "rule.uuid"

	RuleIDKey = "rule.id"

	RuleVersionKey = "rule.version"

	RuleNameKey = "rule.name"

	RuleRulesetKey = "rule.ruleset"

	RuleDescriptionKey = "rule.description"

	RuleCategoryKey = "rule.category"

	ServerPacketsKey = "server.packets"

	ServerRegisteredDomainKey = "server.registered_domain"

	ServerDomainKey = "server.domain"

	ServerPortKey = "server.port"

	ServerTopLevelDomainKey = "server.top_level_domain"

	ServerIPKey = "server.ip"

	ServerBytesKey = "server.bytes"

	ServerAddressKey = "server.address"

	ServerMACKey = "server.mac"

	ServerAsNumberKey = "server.as.number"

	ServerAsOrganizationNameKey = "server.as.organization.name"

	ServerGeoContinentNameKey = "server.geo.continent_name"

	ServerGeoRegionNameKey = "server.geo.region_name"

	ServerGeoRegionIsoCodeKey = "server.geo.region_iso_code"

	ServerGeoLocationKey = "server.geo.location"

	ServerGeoCountryIsoCodeKey = "server.geo.country_iso_code"

	ServerGeoNameKey = "server.geo.name"

	ServerGeoCountryNameKey = "server.geo.country_name"

	ServerGeoCityNameKey = "server.geo.city_name"

	ServerNatIPKey = "server.nat.ip"

	ServerNatPortKey = "server.nat.port"

	ServerUserFullNameKey = "server.user.full_name"

	ServerUserEmailKey = "server.user.email"

	ServerUserDomainKey = "server.user.domain"

	ServerUserHashKey = "server.user.hash"

	ServerUserNameKey = "server.user.name"

	ServerUserIDKey = "server.user.id"

	ServerUserGroupNameKey = "server.user.group.name"

	ServerUserGroupDomainKey = "server.user.group.domain"

	ServerUserGroupIDKey = "server.user.group.id"

	ServiceVersionKey = "service.version"

	ServiceStateKey = "service.state"

	ServiceEphemeralIDKey = "service.ephemeral_id"

	ServiceNameKey = "service.name"

	ServiceIDKey = "service.id"

	ServiceTypeKey = "service.type"

	ServiceNodeNameKey = "service.node.name"

	SourceDomainKey = "source.domain"

	SourceMACKey = "source.mac"

	SourceBytesKey = "source.bytes"

	SourceIPKey = "source.ip"

	SourceTopLevelDomainKey = "source.top_level_domain"

	SourcePortKey = "source.port"

	SourceAddressKey = "source.address"

	SourceRegisteredDomainKey = "source.registered_domain"

	SourcePacketsKey = "source.packets"

	SourceAsNumberKey = "source.as.number"

	SourceAsOrganizationNameKey = "source.as.organization.name"

	SourceGeoCityNameKey = "source.geo.city_name"

	SourceGeoContinentNameKey = "source.geo.continent_name"

	SourceGeoRegionIsoCodeKey = "source.geo.region_iso_code"

	SourceGeoCountryIsoCodeKey = "source.geo.country_iso_code"

	SourceGeoRegionNameKey = "source.geo.region_name"

	SourceGeoLocationKey = "source.geo.location"

	SourceGeoNameKey = "source.geo.name"

	SourceGeoCountryNameKey = "source.geo.country_name"

	SourceNatIPKey = "source.nat.ip"

	SourceNatPortKey = "source.nat.port"

	SourceUserHashKey = "source.user.hash"

	SourceUserNameKey = "source.user.name"

	SourceUserDomainKey = "source.user.domain"

	SourceUserEmailKey = "source.user.email"

	SourceUserFullNameKey = "source.user.full_name"

	SourceUserIDKey = "source.user.id"

	SourceUserGroupIDKey = "source.user.group.id"

	SourceUserGroupNameKey = "source.user.group.name"

	SourceUserGroupDomainKey = "source.user.group.domain"

	ThreatFrameworkKey = "threat.framework"

	ThreatTacticReferenceKey = "threat.tactic.reference"

	ThreatTacticIDKey = "threat.tactic.id"

	ThreatTacticNameKey = "threat.tactic.name"

	ThreatTechniqueIDKey = "threat.technique.id"

	ThreatTechniqueReferenceKey = "threat.technique.reference"

	ThreatTechniqueNameKey = "threat.technique.name"

	TLSCurveKey = "tls.curve"

	TLSResumedKey = "tls.resumed"

	TLSNextProtocolKey = "tls.next_protocol"

	TLSVersionKey = "tls.version"

	TLSEstablishedKey = "tls.established"

	TLSCipherKey = "tls.cipher"

	TLSVersionProtocolKey = "tls.version_protocol"

	TLSClientSubjectKey = "tls.client.subject"

	TLSClientCertificateKey = "tls.client.certificate"

	TLSClientCertificateChainKey = "tls.client.certificate_chain"

	TLSClientSupportedCiphersKey = "tls.client.supported_ciphers"

	TLSClientNotBeforeKey = "tls.client.not_before"

	TLSClientNotAfterKey = "tls.client.not_after"

	TLSClientJa3Key = "tls.client.ja3"

	TLSClientServerNameKey = "tls.client.server_name"

	TLSClientIssuerKey = "tls.client.issuer"

	TLSClientHashSha1Key = "tls.client.hash.sha1"

	TLSClientHashSha256Key = "tls.client.hash.sha256"

	TLSClientHashMd5Key = "tls.client.hash.md5"

	TLSServerJa3sKey = "tls.server.ja3s"

	TLSServerCertificateKey = "tls.server.certificate"

	TLSServerIssuerKey = "tls.server.issuer"

	TLSServerCertificateChainKey = "tls.server.certificate_chain"

	TLSServerNotBeforeKey = "tls.server.not_before"

	TLSServerNotAfterKey = "tls.server.not_after"

	TLSServerSubjectKey = "tls.server.subject"

	TLSServerHashSha1Key = "tls.server.hash.sha1"

	TLSServerHashMd5Key = "tls.server.hash.md5"

	TLSServerHashSha256Key = "tls.server.hash.sha256"

	TraceIDKey = "trace.id"

	TransactionIDKey = "transaction.id"

	URLTopLevelDomainKey = "url.top_level_domain"

	URLExtensionKey = "url.extension"

	URLUsernameKey = "url.username"

	URLPortKey = "url.port"

	URLPasswordKey = "url.password"

	URLFullKey = "url.full"

	URLDomainKey = "url.domain"

	URLQueryKey = "url.query"

	URLOriginalKey = "url.original"

	URLRegisteredDomainKey = "url.registered_domain"

	URLFragmentKey = "url.fragment"

	URLSchemeKey = "url.scheme"

	URLPathKey = "url.path"

	UserFullNameKey = "user.full_name"

	UserNameKey = "user.name"

	UserIDKey = "user.id"

	UserEmailKey = "user.email"

	UserDomainKey = "user.domain"

	UserHashKey = "user.hash"

	UserGroupDomainKey = "user.group.domain"

	UserGroupNameKey = "user.group.name"

	UserGroupIDKey = "user.group.id"

	UserAgentOriginalKey = "user_agent.original"

	UserAgentVersionKey = "user_agent.version"

	UserAgentNameKey = "user_agent.name"

	UserAgentDeviceNameKey = "user_agent.device.name"

	UserAgentOSVersionKey = "user_agent.os.version"

	UserAgentOSFamilyKey = "user_agent.os.family"

	UserAgentOSFullKey = "user_agent.os.full"

	UserAgentOSNameKey = "user_agent.os.name"

	UserAgentOSKernelKey = "user_agent.os.kernel"

	UserAgentOSPlatformKey = "user_agent.os.platform"

	VlanNameKey = "vlan.name"

	VlanIDKey = "vlan.id"

	VulnerabilityCategoryKey = "vulnerability.category"

	VulnerabilityClassificationKey = "vulnerability.classification"

	VulnerabilitySeverityKey = "vulnerability.severity"

	VulnerabilityReportIDKey = "vulnerability.report_id"

	VulnerabilityIDKey = "vulnerability.id"

	VulnerabilityDescriptionKey = "vulnerability.description"

	VulnerabilityReferenceKey = "vulnerability.reference"

	VulnerabilityEnumerationKey = "vulnerability.enumeration"

	VulnerabilityScannerVendorKey = "vulnerability.scanner.vendor"

	VulnerabilityScoreBaseKey = "vulnerability.score.base"

	VulnerabilityScoreEnvironmentalKey = "vulnerability.score.environmental"

	VulnerabilityScoreTemporalKey = "vulnerability.score.temporal"

	VulnerabilityScoreVersionKey = "vulnerability.score.version"
)

var (

	// Agent provides fields in the ECS agent namespace.
	Agent = nsAgent{}

	// As provides fields in the ECS as namespace.
	As = nsAs{}

	// Client provides fields in the ECS client namespace.
	Client = nsClient{}

	// Cloud provides fields in the ECS cloud namespace.
	Cloud = nsCloud{}

	// CodeSignature provides fields in the ECS code_signature namespace.
	CodeSignature = nsCodeSignature{}

	// Container provides fields in the ECS container namespace.
	Container = nsContainer{}

	// Destination provides fields in the ECS destination namespace.
	Destination = nsDestination{}

	// Dll provides fields in the ECS dll namespace.
	Dll = nsDll{}

	// DNS provides fields in the ECS dns namespace.
	DNS = nsDNS{}

	// ECS provides fields in the ECS ecs namespace.
	ECS = nsECS{}

	// Error provides fields in the ECS error namespace.
	Error = nsError{}

	// Event provides fields in the ECS event namespace.
	Event = nsEvent{}

	// File provides fields in the ECS file namespace.
	File = nsFile{}

	// Geo provides fields in the ECS geo namespace.
	Geo = nsGeo{}

	// Group provides fields in the ECS group namespace.
	Group = nsGroup{}

	// Hash provides fields in the ECS hash namespace.
	Hash = nsHash{}

	// Host provides fields in the ECS host namespace.
	Host = nsHost{}

	// HTTP provides fields in the ECS http namespace.
	HTTP = nsHTTP{}

	// Interface provides fields in the ECS interface namespace.
	Interface = nsInterface{}

	// Log provides fields in the ECS log namespace.
	Log = nsLog{}

	// Network provides fields in the ECS network namespace.
	Network = nsNetwork{}

	// Observer provides fields in the ECS observer namespace.
	Observer = nsObserver{}

	// Organization provides fields in the ECS organization namespace.
	Organization = nsOrganization{}

	// OS provides fields in the ECS os namespace.
	OS = nsOS{}

	// Package provides fields in the ECS package namespace.
	Package = nsPackage{}

	// Pe provides fields in the ECS pe namespace.
	Pe = nsPe{}

	// Process provides fields in the ECS process namespace.
	Process = nsProcess{}

	// Registry provides fields in the ECS registry namespace.
	Registry = nsRegistry{}

	// Related provides fields in the ECS related namespace.
	Related = nsRelated{}

	// Rule provides fields in the ECS rule namespace.
	Rule = nsRule{}

	// Server provides fields in the ECS server namespace.
	Server = nsServer{}

	// Service provides fields in the ECS service namespace.
	Service = nsService{}

	// Source provides fields in the ECS source namespace.
	Source = nsSource{}

	// Threat provides fields in the ECS threat namespace.
	Threat = nsThreat{}

	// TLS provides fields in the ECS tls namespace.
	TLS = nsTLS{}

	// Trace provides fields in the ECS trace namespace.
	Trace = nsTrace{}

	// Transaction provides fields in the ECS transaction namespace.
	Transaction = nsTransaction{}

	// URL provides fields in the ECS url namespace.
	URL = nsURL{}

	// User provides fields in the ECS user namespace.
	User = nsUser{}

	// UserAgent provides fields in the ECS user_agent namespace.
	UserAgent = nsUserAgent{}

	// Vlan provides fields in the ECS vlan namespace.
	Vlan = nsVlan{}

	// Vulnerability provides fields in the ECS vulnerability namespace.
	Vulnerability = nsVulnerability{}
)

// Timestamp create the ECS compliant '@timestamp' field.
// Date/time when the event originated. This is the date/time extracted
// from the event, typically representing when the event was generated by
// the source. If the event source has no original timestamp, this value
// is typically populated by the first time the event was received by the
// pipeline. Required field for all events.
func Timestamp(value time.Time) zapcore.Field {
	return ecsTime("@timestamp", value)
}

// Message create the ECS compliant 'message' field.
// For log events the message field contains the log message, optimized
// for viewing in a log viewer. For structured logs without an original
// message field, other fields can be concatenated to form a
// human-readable summary of the event. If multiple messages exist, they
// can be combined into one message.
func Message(value string) zapcore.Field {
	return ecsString("message", value)
}

// Tags create the ECS compliant 'tags' field.
// List of keywords used to tag each event.
func Tags(value string) zapcore.Field {
	return ecsString("tags", value)
}

// ## agent fields

// Type create the ECS compliant 'agent.type' field.
// Type of the agent. The agent type stays always the same and should be
// given by the agent used. In case of Filebeat the agent would always be
// Filebeat also if two Filebeat instances are run on the same machine.
func (nsAgent) Type(value string) zapcore.Field {
	return ecsString("agent.type", value)
}

// EphemeralID create the ECS compliant 'agent.ephemeral_id' field.
// Ephemeral identifier of this agent (if one exists). This id normally
// changes across restarts, but `agent.id` does not.
func (nsAgent) EphemeralID(value string) zapcore.Field {
	return ecsString("agent.ephemeral_id", value)
}

// Version create the ECS compliant 'agent.version' field.
// Version of the agent.
func (nsAgent) Version(value string) zapcore.Field {
	return ecsString("agent.version", value)
}

// Name create the ECS compliant 'agent.name' field.
// Custom name of the agent. This is a name that can be given to an agent.
// This can be helpful if for example two Filebeat instances are running
// on the same host but a human readable separation is needed on which
// Filebeat instance data is coming from. If no name is given, the name is
// often left empty.
func (nsAgent) Name(value string) zapcore.Field {
	return ecsString("agent.name", value)
}

// ID create the ECS compliant 'agent.id' field.
// Unique identifier of this agent (if one exists). Example: For Beats
// this would be beat.id.
func (nsAgent) ID(value string) zapcore.Field {
	return ecsString("agent.id", value)
}

// ## as fields

// Number create the ECS compliant 'as.number' field.
// Unique number allocated to the autonomous system. The autonomous system
// number (ASN) uniquely identifies each network on the Internet.
func (nsAs) Number(value int64) zapcore.Field {
	return ecsInt64("as.number", value)
}

// ## as.organization fields

// Name create the ECS compliant 'as.organization.name' field.
// Organization name.
func (nsAsOrganization) Name(value string) zapcore.Field {
	return ecsString("as.organization.name", value)
}

// ## client fields

// IP create the ECS compliant 'client.ip' field.
// IP address of the client. Can be one or multiple IPv4 or IPv6
// addresses.
func (nsClient) IP(value string) zapcore.Field {
	return ecsString("client.ip", value)
}

// Address create the ECS compliant 'client.address' field.
// Some event client addresses are defined ambiguously. The event will
// sometimes list an IP, a domain or a unix socket.  You should always
// store the raw address in the `.address` field. Then it should be
// duplicated to `.ip` or `.domain`, depending on which one it is.
func (nsClient) Address(value string) zapcore.Field {
	return ecsString("client.address", value)
}

// TopLevelDomain create the ECS compliant 'client.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (nsClient) TopLevelDomain(value string) zapcore.Field {
	return ecsString("client.top_level_domain", value)
}

// Bytes create the ECS compliant 'client.bytes' field.
// Bytes sent from the client to the server.
func (nsClient) Bytes(value int64) zapcore.Field {
	return ecsInt64("client.bytes", value)
}

// RegisteredDomain create the ECS compliant 'client.registered_domain' field.
// The highest registered client domain, stripped of the subdomain. For
// example, the registered domain for "foo.google.com" is "google.com".
// This value can be determined precisely with a list like the public
// suffix list (http://publicsuffix.org). Trying to approximate this by
// simply taking the last two labels will not work well for TLDs such as
// "co.uk".
func (nsClient) RegisteredDomain(value string) zapcore.Field {
	return ecsString("client.registered_domain", value)
}

// Packets create the ECS compliant 'client.packets' field.
// Packets sent from the client to the server.
func (nsClient) Packets(value int64) zapcore.Field {
	return ecsInt64("client.packets", value)
}

// Port create the ECS compliant 'client.port' field.
// Port of the client.
func (nsClient) Port(value int64) zapcore.Field {
	return ecsInt64("client.port", value)
}

// Domain create the ECS compliant 'client.domain' field.
// Client domain.
func (nsClient) Domain(value string) zapcore.Field {
	return ecsString("client.domain", value)
}

// MAC create the ECS compliant 'client.mac' field.
// MAC address of the client.
func (nsClient) MAC(value string) zapcore.Field {
	return ecsString("client.mac", value)
}

// ## client.as fields

// Number create the ECS compliant 'client.as.number' field.
// Unique number allocated to the autonomous system. The autonomous system
// number (ASN) uniquely identifies each network on the Internet.
func (nsClientAs) Number(value int64) zapcore.Field {
	return ecsInt64("client.as.number", value)
}

// ## client.as.organization fields

// Name create the ECS compliant 'client.as.organization.name' field.
// Organization name.
func (nsClientAsOrganization) Name(value string) zapcore.Field {
	return ecsString("client.as.organization.name", value)
}

// ## client.geo fields

// ContinentName create the ECS compliant 'client.geo.continent_name' field.
// Name of the continent.
func (nsClientGeo) ContinentName(value string) zapcore.Field {
	return ecsString("client.geo.continent_name", value)
}

// Name create the ECS compliant 'client.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (nsClientGeo) Name(value string) zapcore.Field {
	return ecsString("client.geo.name", value)
}

// RegionName create the ECS compliant 'client.geo.region_name' field.
// Region name.
func (nsClientGeo) RegionName(value string) zapcore.Field {
	return ecsString("client.geo.region_name", value)
}

// Location create the ECS compliant 'client.geo.location' field.
// Longitude and latitude.
func (nsClientGeo) Location(value string) zapcore.Field {
	return ecsString("client.geo.location", value)
}

// CountryIsoCode create the ECS compliant 'client.geo.country_iso_code' field.
// Country ISO code.
func (nsClientGeo) CountryIsoCode(value string) zapcore.Field {
	return ecsString("client.geo.country_iso_code", value)
}

// RegionIsoCode create the ECS compliant 'client.geo.region_iso_code' field.
// Region ISO code.
func (nsClientGeo) RegionIsoCode(value string) zapcore.Field {
	return ecsString("client.geo.region_iso_code", value)
}

// CityName create the ECS compliant 'client.geo.city_name' field.
// City name.
func (nsClientGeo) CityName(value string) zapcore.Field {
	return ecsString("client.geo.city_name", value)
}

// CountryName create the ECS compliant 'client.geo.country_name' field.
// Country name.
func (nsClientGeo) CountryName(value string) zapcore.Field {
	return ecsString("client.geo.country_name", value)
}

// ## client.nat fields

// Port create the ECS compliant 'client.nat.port' field.
// Translated port of source based NAT sessions (e.g. internal client to
// internet). Typically connections traversing load balancers, firewalls,
// or routers.
func (nsClientNat) Port(value int64) zapcore.Field {
	return ecsInt64("client.nat.port", value)
}

// IP create the ECS compliant 'client.nat.ip' field.
// Translated IP of source based NAT sessions (e.g. internal client to
// internet). Typically connections traversing load balancers, firewalls,
// or routers.
func (nsClientNat) IP(value string) zapcore.Field {
	return ecsString("client.nat.ip", value)
}

// ## client.user fields

// Domain create the ECS compliant 'client.user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsClientUser) Domain(value string) zapcore.Field {
	return ecsString("client.user.domain", value)
}

// FullName create the ECS compliant 'client.user.full_name' field.
// User's full name, if available.
func (nsClientUser) FullName(value string) zapcore.Field {
	return ecsString("client.user.full_name", value)
}

// Name create the ECS compliant 'client.user.name' field.
// Short name or login of the user.
func (nsClientUser) Name(value string) zapcore.Field {
	return ecsString("client.user.name", value)
}

// Hash create the ECS compliant 'client.user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (nsClientUser) Hash(value string) zapcore.Field {
	return ecsString("client.user.hash", value)
}

// Email create the ECS compliant 'client.user.email' field.
// User email address.
func (nsClientUser) Email(value string) zapcore.Field {
	return ecsString("client.user.email", value)
}

// ID create the ECS compliant 'client.user.id' field.
// Unique identifiers of the user.
func (nsClientUser) ID(value string) zapcore.Field {
	return ecsString("client.user.id", value)
}

// ## client.user.group fields

// Name create the ECS compliant 'client.user.group.name' field.
// Name of the group.
func (nsClientUserGroup) Name(value string) zapcore.Field {
	return ecsString("client.user.group.name", value)
}

// ID create the ECS compliant 'client.user.group.id' field.
// Unique identifier for the group on the system/platform.
func (nsClientUserGroup) ID(value string) zapcore.Field {
	return ecsString("client.user.group.id", value)
}

// Domain create the ECS compliant 'client.user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsClientUserGroup) Domain(value string) zapcore.Field {
	return ecsString("client.user.group.domain", value)
}

// ## cloud fields

// Region create the ECS compliant 'cloud.region' field.
// Region in which this host is running.
func (nsCloud) Region(value string) zapcore.Field {
	return ecsString("cloud.region", value)
}

// AvailabilityZone create the ECS compliant 'cloud.availability_zone' field.
// Availability zone in which this host is running.
func (nsCloud) AvailabilityZone(value string) zapcore.Field {
	return ecsString("cloud.availability_zone", value)
}

// Provider create the ECS compliant 'cloud.provider' field.
// Name of the cloud provider. Example values are aws, azure, gcp, or
// digitalocean.
func (nsCloud) Provider(value string) zapcore.Field {
	return ecsString("cloud.provider", value)
}

// ## cloud.account fields

// ID create the ECS compliant 'cloud.account.id' field.
// The cloud account or organization id used to identify different
// entities in a multi-tenant environment. Examples: AWS account id,
// Google Cloud ORG Id, or other unique identifier.
func (nsCloudAccount) ID(value string) zapcore.Field {
	return ecsString("cloud.account.id", value)
}

// ## cloud.instance fields

// ID create the ECS compliant 'cloud.instance.id' field.
// Instance ID of the host machine.
func (nsCloudInstance) ID(value string) zapcore.Field {
	return ecsString("cloud.instance.id", value)
}

// Name create the ECS compliant 'cloud.instance.name' field.
// Instance name of the host machine.
func (nsCloudInstance) Name(value string) zapcore.Field {
	return ecsString("cloud.instance.name", value)
}

// ## cloud.machine fields

// Type create the ECS compliant 'cloud.machine.type' field.
// Machine type of the host machine.
func (nsCloudMachine) Type(value string) zapcore.Field {
	return ecsString("cloud.machine.type", value)
}

// ## code_signature fields

// Valid create the ECS compliant 'code_signature.valid' field.
// Boolean to capture if the digital signature is verified against the
// binary content. Leave unpopulated if a certificate was unchecked.
func (nsCodeSignature) Valid(value bool) zapcore.Field {
	return ecsBool("code_signature.valid", value)
}

// Trusted create the ECS compliant 'code_signature.trusted' field.
// Stores the trust status of the certificate chain. Validating the trust
// of the certificate chain may be complicated, and this field should only
// be populated by tools that actively check the status.
func (nsCodeSignature) Trusted(value bool) zapcore.Field {
	return ecsBool("code_signature.trusted", value)
}

// Exists create the ECS compliant 'code_signature.exists' field.
// Boolean to capture if a signature is present.
func (nsCodeSignature) Exists(value bool) zapcore.Field {
	return ecsBool("code_signature.exists", value)
}

// SubjectName create the ECS compliant 'code_signature.subject_name' field.
// Subject name of the code signer
func (nsCodeSignature) SubjectName(value string) zapcore.Field {
	return ecsString("code_signature.subject_name", value)
}

// Status create the ECS compliant 'code_signature.status' field.
// Additional information about the certificate status. This is useful for
// logging cryptographic errors with the certificate validity or trust
// status. Leave unpopulated if the validity or trust of the certificate
// was unchecked.
func (nsCodeSignature) Status(value string) zapcore.Field {
	return ecsString("code_signature.status", value)
}

// ## container fields

// ID create the ECS compliant 'container.id' field.
// Unique container id.
func (nsContainer) ID(value string) zapcore.Field {
	return ecsString("container.id", value)
}

// Runtime create the ECS compliant 'container.runtime' field.
// Runtime managing this container.
func (nsContainer) Runtime(value string) zapcore.Field {
	return ecsString("container.runtime", value)
}

// Name create the ECS compliant 'container.name' field.
// Container name.
func (nsContainer) Name(value string) zapcore.Field {
	return ecsString("container.name", value)
}

// ## container.image fields

// Name create the ECS compliant 'container.image.name' field.
// Name of the image the container was built on.
func (nsContainerImage) Name(value string) zapcore.Field {
	return ecsString("container.image.name", value)
}

// Tag create the ECS compliant 'container.image.tag' field.
// Container image tags.
func (nsContainerImage) Tag(value string) zapcore.Field {
	return ecsString("container.image.tag", value)
}

// ## destination fields

// Domain create the ECS compliant 'destination.domain' field.
// Destination domain.
func (nsDestination) Domain(value string) zapcore.Field {
	return ecsString("destination.domain", value)
}

// IP create the ECS compliant 'destination.ip' field.
// IP address of the destination. Can be one or multiple IPv4 or IPv6
// addresses.
func (nsDestination) IP(value string) zapcore.Field {
	return ecsString("destination.ip", value)
}

// MAC create the ECS compliant 'destination.mac' field.
// MAC address of the destination.
func (nsDestination) MAC(value string) zapcore.Field {
	return ecsString("destination.mac", value)
}

// Packets create the ECS compliant 'destination.packets' field.
// Packets sent from the destination to the source.
func (nsDestination) Packets(value int64) zapcore.Field {
	return ecsInt64("destination.packets", value)
}

// RegisteredDomain create the ECS compliant 'destination.registered_domain' field.
// The highest registered destination domain, stripped of the subdomain.
// For example, the registered domain for "foo.google.com" is
// "google.com". This value can be determined precisely with a list like
// the public suffix list (http://publicsuffix.org). Trying to approximate
// this by simply taking the last two labels will not work well for TLDs
// such as "co.uk".
func (nsDestination) RegisteredDomain(value string) zapcore.Field {
	return ecsString("destination.registered_domain", value)
}

// Address create the ECS compliant 'destination.address' field.
// Some event destination addresses are defined ambiguously. The event
// will sometimes list an IP, a domain or a unix socket.  You should
// always store the raw address in the `.address` field. Then it should be
// duplicated to `.ip` or `.domain`, depending on which one it is.
func (nsDestination) Address(value string) zapcore.Field {
	return ecsString("destination.address", value)
}

// Port create the ECS compliant 'destination.port' field.
// Port of the destination.
func (nsDestination) Port(value int64) zapcore.Field {
	return ecsInt64("destination.port", value)
}

// TopLevelDomain create the ECS compliant 'destination.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (nsDestination) TopLevelDomain(value string) zapcore.Field {
	return ecsString("destination.top_level_domain", value)
}

// Bytes create the ECS compliant 'destination.bytes' field.
// Bytes sent from the destination to the source.
func (nsDestination) Bytes(value int64) zapcore.Field {
	return ecsInt64("destination.bytes", value)
}

// ## destination.as fields

// Number create the ECS compliant 'destination.as.number' field.
// Unique number allocated to the autonomous system. The autonomous system
// number (ASN) uniquely identifies each network on the Internet.
func (nsDestinationAs) Number(value int64) zapcore.Field {
	return ecsInt64("destination.as.number", value)
}

// ## destination.as.organization fields

// Name create the ECS compliant 'destination.as.organization.name' field.
// Organization name.
func (nsDestinationAsOrganization) Name(value string) zapcore.Field {
	return ecsString("destination.as.organization.name", value)
}

// ## destination.geo fields

// CountryName create the ECS compliant 'destination.geo.country_name' field.
// Country name.
func (nsDestinationGeo) CountryName(value string) zapcore.Field {
	return ecsString("destination.geo.country_name", value)
}

// Location create the ECS compliant 'destination.geo.location' field.
// Longitude and latitude.
func (nsDestinationGeo) Location(value string) zapcore.Field {
	return ecsString("destination.geo.location", value)
}

// RegionIsoCode create the ECS compliant 'destination.geo.region_iso_code' field.
// Region ISO code.
func (nsDestinationGeo) RegionIsoCode(value string) zapcore.Field {
	return ecsString("destination.geo.region_iso_code", value)
}

// ContinentName create the ECS compliant 'destination.geo.continent_name' field.
// Name of the continent.
func (nsDestinationGeo) ContinentName(value string) zapcore.Field {
	return ecsString("destination.geo.continent_name", value)
}

// CountryIsoCode create the ECS compliant 'destination.geo.country_iso_code' field.
// Country ISO code.
func (nsDestinationGeo) CountryIsoCode(value string) zapcore.Field {
	return ecsString("destination.geo.country_iso_code", value)
}

// CityName create the ECS compliant 'destination.geo.city_name' field.
// City name.
func (nsDestinationGeo) CityName(value string) zapcore.Field {
	return ecsString("destination.geo.city_name", value)
}

// Name create the ECS compliant 'destination.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (nsDestinationGeo) Name(value string) zapcore.Field {
	return ecsString("destination.geo.name", value)
}

// RegionName create the ECS compliant 'destination.geo.region_name' field.
// Region name.
func (nsDestinationGeo) RegionName(value string) zapcore.Field {
	return ecsString("destination.geo.region_name", value)
}

// ## destination.nat fields

// Port create the ECS compliant 'destination.nat.port' field.
// Port the source session is translated to by NAT Device. Typically used
// with load balancers, firewalls, or routers.
func (nsDestinationNat) Port(value int64) zapcore.Field {
	return ecsInt64("destination.nat.port", value)
}

// IP create the ECS compliant 'destination.nat.ip' field.
// Translated ip of destination based NAT sessions (e.g. internet to
// private DMZ) Typically used with load balancers, firewalls, or routers.
func (nsDestinationNat) IP(value string) zapcore.Field {
	return ecsString("destination.nat.ip", value)
}

// ## destination.user fields

// Domain create the ECS compliant 'destination.user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsDestinationUser) Domain(value string) zapcore.Field {
	return ecsString("destination.user.domain", value)
}

// ID create the ECS compliant 'destination.user.id' field.
// Unique identifiers of the user.
func (nsDestinationUser) ID(value string) zapcore.Field {
	return ecsString("destination.user.id", value)
}

// Hash create the ECS compliant 'destination.user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (nsDestinationUser) Hash(value string) zapcore.Field {
	return ecsString("destination.user.hash", value)
}

// FullName create the ECS compliant 'destination.user.full_name' field.
// User's full name, if available.
func (nsDestinationUser) FullName(value string) zapcore.Field {
	return ecsString("destination.user.full_name", value)
}

// Name create the ECS compliant 'destination.user.name' field.
// Short name or login of the user.
func (nsDestinationUser) Name(value string) zapcore.Field {
	return ecsString("destination.user.name", value)
}

// Email create the ECS compliant 'destination.user.email' field.
// User email address.
func (nsDestinationUser) Email(value string) zapcore.Field {
	return ecsString("destination.user.email", value)
}

// ## destination.user.group fields

// Domain create the ECS compliant 'destination.user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsDestinationUserGroup) Domain(value string) zapcore.Field {
	return ecsString("destination.user.group.domain", value)
}

// ID create the ECS compliant 'destination.user.group.id' field.
// Unique identifier for the group on the system/platform.
func (nsDestinationUserGroup) ID(value string) zapcore.Field {
	return ecsString("destination.user.group.id", value)
}

// Name create the ECS compliant 'destination.user.group.name' field.
// Name of the group.
func (nsDestinationUserGroup) Name(value string) zapcore.Field {
	return ecsString("destination.user.group.name", value)
}

// ## dll fields

// Name create the ECS compliant 'dll.name' field.
// Name of the library. This generally maps to the name of the file on
// disk.
func (nsDll) Name(value string) zapcore.Field {
	return ecsString("dll.name", value)
}

// Path create the ECS compliant 'dll.path' field.
// Full file path of the library.
func (nsDll) Path(value string) zapcore.Field {
	return ecsString("dll.path", value)
}

// ## dll.code_signature fields

// Exists create the ECS compliant 'dll.code_signature.exists' field.
// Boolean to capture if a signature is present.
func (nsDllCodeSignature) Exists(value bool) zapcore.Field {
	return ecsBool("dll.code_signature.exists", value)
}

// Valid create the ECS compliant 'dll.code_signature.valid' field.
// Boolean to capture if the digital signature is verified against the
// binary content. Leave unpopulated if a certificate was unchecked.
func (nsDllCodeSignature) Valid(value bool) zapcore.Field {
	return ecsBool("dll.code_signature.valid", value)
}

// SubjectName create the ECS compliant 'dll.code_signature.subject_name' field.
// Subject name of the code signer
func (nsDllCodeSignature) SubjectName(value string) zapcore.Field {
	return ecsString("dll.code_signature.subject_name", value)
}

// Trusted create the ECS compliant 'dll.code_signature.trusted' field.
// Stores the trust status of the certificate chain. Validating the trust
// of the certificate chain may be complicated, and this field should only
// be populated by tools that actively check the status.
func (nsDllCodeSignature) Trusted(value bool) zapcore.Field {
	return ecsBool("dll.code_signature.trusted", value)
}

// Status create the ECS compliant 'dll.code_signature.status' field.
// Additional information about the certificate status. This is useful for
// logging cryptographic errors with the certificate validity or trust
// status. Leave unpopulated if the validity or trust of the certificate
// was unchecked.
func (nsDllCodeSignature) Status(value string) zapcore.Field {
	return ecsString("dll.code_signature.status", value)
}

// ## dll.hash fields

// Md5 create the ECS compliant 'dll.hash.md5' field.
// MD5 hash.
func (nsDllHash) Md5(value string) zapcore.Field {
	return ecsString("dll.hash.md5", value)
}

// Sha256 create the ECS compliant 'dll.hash.sha256' field.
// SHA256 hash.
func (nsDllHash) Sha256(value string) zapcore.Field {
	return ecsString("dll.hash.sha256", value)
}

// Sha1 create the ECS compliant 'dll.hash.sha1' field.
// SHA1 hash.
func (nsDllHash) Sha1(value string) zapcore.Field {
	return ecsString("dll.hash.sha1", value)
}

// Sha512 create the ECS compliant 'dll.hash.sha512' field.
// SHA512 hash.
func (nsDllHash) Sha512(value string) zapcore.Field {
	return ecsString("dll.hash.sha512", value)
}

// ## dll.pe fields

// Description create the ECS compliant 'dll.pe.description' field.
// Internal description of the file, provided at compile-time.
func (nsDllPe) Description(value string) zapcore.Field {
	return ecsString("dll.pe.description", value)
}

// Product create the ECS compliant 'dll.pe.product' field.
// Internal product name of the file, provided at compile-time.
func (nsDllPe) Product(value string) zapcore.Field {
	return ecsString("dll.pe.product", value)
}

// OriginalFileName create the ECS compliant 'dll.pe.original_file_name' field.
// Internal name of the file, provided at compile-time.
func (nsDllPe) OriginalFileName(value string) zapcore.Field {
	return ecsString("dll.pe.original_file_name", value)
}

// Company create the ECS compliant 'dll.pe.company' field.
// Internal company name of the file, provided at compile-time.
func (nsDllPe) Company(value string) zapcore.Field {
	return ecsString("dll.pe.company", value)
}

// FileVersion create the ECS compliant 'dll.pe.file_version' field.
// Internal version of the file, provided at compile-time.
func (nsDllPe) FileVersion(value string) zapcore.Field {
	return ecsString("dll.pe.file_version", value)
}

// ## dns fields

// ID create the ECS compliant 'dns.id' field.
// The DNS packet identifier assigned by the program that generated the
// query. The identifier is copied to the response.
func (nsDNS) ID(value string) zapcore.Field {
	return ecsString("dns.id", value)
}

// ResponseCode create the ECS compliant 'dns.response_code' field.
// The DNS response code.
func (nsDNS) ResponseCode(value string) zapcore.Field {
	return ecsString("dns.response_code", value)
}

// OpCode create the ECS compliant 'dns.op_code' field.
// The DNS operation code that specifies the kind of query in the message.
// This value is set by the originator of a query and copied into the
// response.
func (nsDNS) OpCode(value string) zapcore.Field {
	return ecsString("dns.op_code", value)
}

// ResolvedIP create the ECS compliant 'dns.resolved_ip' field.
// Array containing all IPs seen in `answers.data`. The `answers` array
// can be difficult to use, because of the variety of data formats it can
// contain. Extracting all IP addresses seen in there to `dns.resolved_ip`
// makes it possible to index them as IP addresses, and makes them easier
// to visualize and query for.
func (nsDNS) ResolvedIP(value string) zapcore.Field {
	return ecsString("dns.resolved_ip", value)
}

// Type create the ECS compliant 'dns.type' field.
// The type of DNS event captured, query or answer. If your source of DNS
// events only gives you DNS queries, you should only create dns events of
// type `dns.type:query`. If your source of DNS events gives you answers
// as well, you should create one event per query (optionally as soon as
// the query is seen). And a second event containing all query details as
// well as an array of answers.
func (nsDNS) Type(value string) zapcore.Field {
	return ecsString("dns.type", value)
}

// HeaderFlags create the ECS compliant 'dns.header_flags' field.
// Array of 2 letter DNS header flags. Expected values are: AA, TC, RD,
// RA, AD, CD, DO.
func (nsDNS) HeaderFlags(value string) zapcore.Field {
	return ecsString("dns.header_flags", value)
}

// ## dns.answers fields

// Class create the ECS compliant 'dns.answers.class' field.
// The class of DNS data contained in this resource record.
func (nsDNSAnswers) Class(value string) zapcore.Field {
	return ecsString("dns.answers.class", value)
}

// Data create the ECS compliant 'dns.answers.data' field.
// The data describing the resource. The meaning of this data depends on
// the type and class of the resource record.
func (nsDNSAnswers) Data(value string) zapcore.Field {
	return ecsString("dns.answers.data", value)
}

// Name create the ECS compliant 'dns.answers.name' field.
// The domain name to which this resource record pertains. If a chain of
// CNAME is being resolved, each answer's `name` should be the one that
// corresponds with the answer's `data`. It should not simply be the
// original `question.name` repeated.
func (nsDNSAnswers) Name(value string) zapcore.Field {
	return ecsString("dns.answers.name", value)
}

// Type create the ECS compliant 'dns.answers.type' field.
// The type of data contained in this resource record.
func (nsDNSAnswers) Type(value string) zapcore.Field {
	return ecsString("dns.answers.type", value)
}

// TTL create the ECS compliant 'dns.answers.ttl' field.
// The time interval in seconds that this resource record may be cached
// before it should be discarded. Zero values mean that the data should
// not be cached.
func (nsDNSAnswers) TTL(value int64) zapcore.Field {
	return ecsInt64("dns.answers.ttl", value)
}

// ## dns.question fields

// TopLevelDomain create the ECS compliant 'dns.question.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (nsDNSQuestion) TopLevelDomain(value string) zapcore.Field {
	return ecsString("dns.question.top_level_domain", value)
}

// Type create the ECS compliant 'dns.question.type' field.
// The type of record being queried.
func (nsDNSQuestion) Type(value string) zapcore.Field {
	return ecsString("dns.question.type", value)
}

// Name create the ECS compliant 'dns.question.name' field.
// The name being queried. If the name field contains non-printable
// characters (below 32 or above 126), those characters should be
// represented as escaped base 10 integers (\DDD). Back slashes and quotes
// should be escaped. Tabs, carriage returns, and line feeds should be
// converted to \t, \r, and \n respectively.
func (nsDNSQuestion) Name(value string) zapcore.Field {
	return ecsString("dns.question.name", value)
}

// RegisteredDomain create the ECS compliant 'dns.question.registered_domain' field.
// The highest registered domain, stripped of the subdomain. For example,
// the registered domain for "foo.google.com" is "google.com". This value
// can be determined precisely with a list like the public suffix list
// (http://publicsuffix.org). Trying to approximate this by simply taking
// the last two labels will not work well for TLDs such as "co.uk".
func (nsDNSQuestion) RegisteredDomain(value string) zapcore.Field {
	return ecsString("dns.question.registered_domain", value)
}

// Subdomain create the ECS compliant 'dns.question.subdomain' field.
// The subdomain is all of the labels under the registered_domain. If the
// domain has multiple levels of subdomain, such as
// "sub2.sub1.example.com", the subdomain field should contain
// "sub2.sub1", with no trailing period.
func (nsDNSQuestion) Subdomain(value string) zapcore.Field {
	return ecsString("dns.question.subdomain", value)
}

// Class create the ECS compliant 'dns.question.class' field.
// The class of records being queried.
func (nsDNSQuestion) Class(value string) zapcore.Field {
	return ecsString("dns.question.class", value)
}

// ## ecs fields

// Version create the ECS compliant 'ecs.version' field.
// ECS version this event conforms to. `ecs.version` is a required field
// and must exist in all events. When querying across multiple indices --
// which may conform to slightly different ECS versions -- this field lets
// integrations adjust to the schema version of the events.
func (nsECS) Version(value string) zapcore.Field {
	return ecsString("ecs.version", value)
}

// ## error fields

// ID create the ECS compliant 'error.id' field.
// Unique identifier for the error.
func (nsError) ID(value string) zapcore.Field {
	return ecsString("error.id", value)
}

// StackTrace create the ECS compliant 'error.stack_trace' field.
// The stack trace of this error in plain text.
func (nsError) StackTrace(value string) zapcore.Field {
	return ecsString("error.stack_trace", value)
}

// Type create the ECS compliant 'error.type' field.
// The type of the error, for example the class name of the exception.
func (nsError) Type(value string) zapcore.Field {
	return ecsString("error.type", value)
}

// Message create the ECS compliant 'error.message' field.
// Error message.
func (nsError) Message(value string) zapcore.Field {
	return ecsString("error.message", value)
}

// Code create the ECS compliant 'error.code' field.
// Error code describing the error.
func (nsError) Code(value string) zapcore.Field {
	return ecsString("error.code", value)
}

// ## event fields

// Kind create the ECS compliant 'event.kind' field.
// This is one of four ECS Categorization Fields, and indicates the
// highest level in the ECS category hierarchy. `event.kind` gives
// high-level information about what type of information the event
// contains, without being specific to the contents of the event. For
// example, values of this field distinguish alert events from metric
// events. The value of this field can be used to inform how these kinds
// of events should be handled. They may warrant different retention,
// different access control, it may also help understand whether the data
// coming in at a regular interval or not.
func (nsEvent) Kind(value string) zapcore.Field {
	return ecsString("event.kind", value)
}

// ID create the ECS compliant 'event.id' field.
// Unique ID to describe the event.
func (nsEvent) ID(value string) zapcore.Field {
	return ecsString("event.id", value)
}

// Code create the ECS compliant 'event.code' field.
// Identification code for this event, if one exists. Some event sources
// use event codes to identify messages unambiguously, regardless of
// message language or wording adjustments over time. An example of this
// is the Windows Event ID.
func (nsEvent) Code(value string) zapcore.Field {
	return ecsString("event.code", value)
}

// Module create the ECS compliant 'event.module' field.
// Name of the module this data is coming from. If your monitoring agent
// supports the concept of modules or plugins to process events of a given
// source (e.g. Apache logs), `event.module` should contain the name of
// this module.
func (nsEvent) Module(value string) zapcore.Field {
	return ecsString("event.module", value)
}

// Original create the ECS compliant 'event.original' field.
// Raw text message of entire event. Used to demonstrate log integrity.
// This field is not indexed and doc_values are disabled. It cannot be
// searched, but it can be retrieved from `_source`.
func (nsEvent) Original(value string) zapcore.Field {
	return ecsString("event.original", value)
}

// RiskScore create the ECS compliant 'event.risk_score' field.
// Risk score or priority of the event (e.g. security solutions). Use your
// system's original value here.
func (nsEvent) RiskScore(value float64) zapcore.Field {
	return ecsFloat64("event.risk_score", value)
}

// Ingested create the ECS compliant 'event.ingested' field.
// Timestamp when an event arrived in the central data store. This is
// different from `@timestamp`, which is when the event originally
// occurred.  It's also different from `event.created`, which is meant to
// capture the first time an agent saw the event. In normal conditions,
// assuming no tampering, the timestamps should chronologically look like
// this: `@timestamp` < `event.created` < `event.ingested`.
func (nsEvent) Ingested(value time.Time) zapcore.Field {
	return ecsTime("event.ingested", value)
}

// Duration create the ECS compliant 'event.duration' field.
// Duration of the event in nanoseconds. If event.start and event.end are
// known this value should be the difference between the end and start
// time.
func (nsEvent) Duration(value int64) zapcore.Field {
	return ecsInt64("event.duration", value)
}

// Category create the ECS compliant 'event.category' field.
// This is one of four ECS Categorization Fields, and indicates the second
// level in the ECS category hierarchy. `event.category` represents the
// "big buckets" of ECS categories. For example, filtering on
// `event.category:process` yields all events relating to process
// activity. This field is closely related to `event.type`, which is used
// as a subcategory. This field is an array. This will allow proper
// categorization of some events that fall in multiple categories.
func (nsEvent) Category(value string) zapcore.Field {
	return ecsString("event.category", value)
}

// Sequence create the ECS compliant 'event.sequence' field.
// Sequence number of the event. The sequence number is a value published
// by some event sources, to make the exact ordering of events
// unambiguous, regardless of the timestamp precision.
func (nsEvent) Sequence(value int64) zapcore.Field {
	return ecsInt64("event.sequence", value)
}

// Hash create the ECS compliant 'event.hash' field.
// Hash (perhaps logstash fingerprint) of raw field to be able to
// demonstrate log integrity.
func (nsEvent) Hash(value string) zapcore.Field {
	return ecsString("event.hash", value)
}

// Action create the ECS compliant 'event.action' field.
// The action captured by the event. This describes the information in the
// event. It is more specific than `event.category`. Examples are
// `group-add`, `process-started`, `file-created`. The value is normally
// defined by the implementer.
func (nsEvent) Action(value string) zapcore.Field {
	return ecsString("event.action", value)
}

// Created create the ECS compliant 'event.created' field.
// event.created contains the date/time when the event was first read by
// an agent, or by your pipeline. This field is distinct from @timestamp
// in that @timestamp typically contain the time extracted from the
// original event. In most situations, these two timestamps will be
// slightly different. The difference can be used to calculate the delay
// between your source generating an event, and the time when your agent
// first processed it. This can be used to monitor your agent's or
// pipeline's ability to keep up with your event source. In case the two
// timestamps are identical, @timestamp should be used.
func (nsEvent) Created(value time.Time) zapcore.Field {
	return ecsTime("event.created", value)
}

// Start create the ECS compliant 'event.start' field.
// event.start contains the date when the event started or when the
// activity was first observed.
func (nsEvent) Start(value time.Time) zapcore.Field {
	return ecsTime("event.start", value)
}

// URL create the ECS compliant 'event.url' field.
// URL linking to an external system to continue investigation of this
// event. This URL links to another system where in-depth investigation of
// the specific occurence of this event can take place. Alert events,
// indicated by `event.kind:alert`, are a common use case for this field.
func (nsEvent) URL(value string) zapcore.Field {
	return ecsString("event.url", value)
}

// Provider create the ECS compliant 'event.provider' field.
// Source of the event. Event transports such as Syslog or the Windows
// Event Log typically mention the source of an event. It can be the name
// of the software that generated the event (e.g. Sysmon, httpd), or of a
// subsystem of the operating system (kernel,
// Microsoft-Windows-Security-Auditing).
func (nsEvent) Provider(value string) zapcore.Field {
	return ecsString("event.provider", value)
}

// End create the ECS compliant 'event.end' field.
// event.end contains the date when the event ended or when the activity
// was last observed.
func (nsEvent) End(value time.Time) zapcore.Field {
	return ecsTime("event.end", value)
}

// RiskScoreNorm create the ECS compliant 'event.risk_score_norm' field.
// Normalized risk score or priority of the event, on a scale of 0 to 100.
// This is mainly useful if you use more than one system that assigns risk
// scores, and you want to see a normalized value across all systems.
func (nsEvent) RiskScoreNorm(value float64) zapcore.Field {
	return ecsFloat64("event.risk_score_norm", value)
}

// Type create the ECS compliant 'event.type' field.
// This is one of four ECS Categorization Fields, and indicates the third
// level in the ECS category hierarchy. `event.type` represents a
// categorization "sub-bucket" that, when used along with the
// `event.category` field values, enables filtering events down to a level
// appropriate for single visualization. This field is an array. This will
// allow proper categorization of some events that fall in multiple event
// types.
func (nsEvent) Type(value string) zapcore.Field {
	return ecsString("event.type", value)
}

// Timezone create the ECS compliant 'event.timezone' field.
// This field should be populated when the event's timestamp does not
// include timezone information already (e.g. default Syslog timestamps).
// It's optional otherwise. Acceptable timezone formats are: a canonical
// ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm
// differential (e.g. "-05:00").
func (nsEvent) Timezone(value string) zapcore.Field {
	return ecsString("event.timezone", value)
}

// Severity create the ECS compliant 'event.severity' field.
// The numeric severity of the event according to your event source. What
// the different severity values mean can be different between sources and
// use cases. It's up to the implementer to make sure severities are
// consistent across events from the same source. The Syslog severity
// belongs in `log.syslog.severity.code`. `event.severity` is meant to
// represent the severity according to the event source (e.g. firewall,
// IDS). If the event source does not publish its own severity, you may
// optionally copy the `log.syslog.severity.code` to `event.severity`.
func (nsEvent) Severity(value int64) zapcore.Field {
	return ecsInt64("event.severity", value)
}

// Outcome create the ECS compliant 'event.outcome' field.
// This is one of four ECS Categorization Fields, and indicates the lowest
// level in the ECS category hierarchy. `event.outcome` simply denotes
// whether the event represents a success or a failure from the
// perspective of the entity that produced the event. Note that when a
// single transaction is described in multiple events, each event may
// populate different values of `event.outcome`, according to their
// perspective. Also note that in the case of a compound event (a single
// event that contains multiple logical events), this field should be
// populated with the value that best captures the overall success or
// failure from the perspective of the event producer. Further note that
// not all events will have an associated outcome. For example, this field
// is generally not populated for metric events, events with
// `event.type:info`, or any events for which an outcome does not make
// logical sense.
func (nsEvent) Outcome(value string) zapcore.Field {
	return ecsString("event.outcome", value)
}

// Reference create the ECS compliant 'event.reference' field.
// Reference URL linking to additional information about this event. This
// URL links to a static definition of the this event. Alert events,
// indicated by `event.kind:alert`, are a common use case for this field.
func (nsEvent) Reference(value string) zapcore.Field {
	return ecsString("event.reference", value)
}

// Dataset create the ECS compliant 'event.dataset' field.
// Name of the dataset. If an event source publishes more than one type of
// log or events (e.g. access log, error log), the dataset is used to
// specify which one the event comes from. It's recommended but not
// required to start the dataset name with the module name, followed by a
// dot, then the dataset name.
func (nsEvent) Dataset(value string) zapcore.Field {
	return ecsString("event.dataset", value)
}

// ## file fields

// Created create the ECS compliant 'file.created' field.
// File creation time. Note that not all filesystems store the creation
// time.
func (nsFile) Created(value time.Time) zapcore.Field {
	return ecsTime("file.created", value)
}

// MimeType create the ECS compliant 'file.mime_type' field.
// MIME type should identify the format of the file or stream of bytes
// using
// https://www.iana.org/assignments/media-types/media-types.xhtml[IANA
// official types], where possible. When more than one type is applicable,
// the most specific type should be used.
func (nsFile) MimeType(value string) zapcore.Field {
	return ecsString("file.mime_type", value)
}

// Gid create the ECS compliant 'file.gid' field.
// Primary group ID (GID) of the file.
func (nsFile) Gid(value string) zapcore.Field {
	return ecsString("file.gid", value)
}

// Ctime create the ECS compliant 'file.ctime' field.
// Last time the file attributes or metadata changed. Note that changes to
// the file content will update `mtime`. This implies `ctime` will be
// adjusted at the same time, since `mtime` is an attribute of the file.
func (nsFile) Ctime(value time.Time) zapcore.Field {
	return ecsTime("file.ctime", value)
}

// Directory create the ECS compliant 'file.directory' field.
// Directory where the file is located. It should include the drive
// letter, when appropriate.
func (nsFile) Directory(value string) zapcore.Field {
	return ecsString("file.directory", value)
}

// Name create the ECS compliant 'file.name' field.
// Name of the file including the extension, without the directory.
func (nsFile) Name(value string) zapcore.Field {
	return ecsString("file.name", value)
}

// UID create the ECS compliant 'file.uid' field.
// The user ID (UID) or security identifier (SID) of the file owner.
func (nsFile) UID(value string) zapcore.Field {
	return ecsString("file.uid", value)
}

// Mtime create the ECS compliant 'file.mtime' field.
// Last time the file content was modified.
func (nsFile) Mtime(value time.Time) zapcore.Field {
	return ecsTime("file.mtime", value)
}

// Group create the ECS compliant 'file.group' field.
// Primary group name of the file.
func (nsFile) Group(value string) zapcore.Field {
	return ecsString("file.group", value)
}

// DriveLetter create the ECS compliant 'file.drive_letter' field.
// Drive letter where the file is located. This field is only relevant on
// Windows. The value should be uppercase, and not include the colon.
func (nsFile) DriveLetter(value string) zapcore.Field {
	return ecsString("file.drive_letter", value)
}

// Path create the ECS compliant 'file.path' field.
// Full path to the file, including the file name. It should include the
// drive letter, when appropriate.
func (nsFile) Path(value string) zapcore.Field {
	return ecsString("file.path", value)
}

// Device create the ECS compliant 'file.device' field.
// Device that is the source of the file.
func (nsFile) Device(value string) zapcore.Field {
	return ecsString("file.device", value)
}

// Extension create the ECS compliant 'file.extension' field.
// File extension.
func (nsFile) Extension(value string) zapcore.Field {
	return ecsString("file.extension", value)
}

// Size create the ECS compliant 'file.size' field.
// File size in bytes. Only relevant when `file.type` is "file".
func (nsFile) Size(value int64) zapcore.Field {
	return ecsInt64("file.size", value)
}

// Owner create the ECS compliant 'file.owner' field.
// File owner's username.
func (nsFile) Owner(value string) zapcore.Field {
	return ecsString("file.owner", value)
}

// Type create the ECS compliant 'file.type' field.
// File type (file, dir, or symlink).
func (nsFile) Type(value string) zapcore.Field {
	return ecsString("file.type", value)
}

// Attributes create the ECS compliant 'file.attributes' field.
// Array of file attributes. Attributes names will vary by platform.
// Here's a non-exhaustive list of values that are expected in this field:
// archive, compressed, directory, encrypted, execute, hidden, read,
// readonly, system, write.
func (nsFile) Attributes(value string) zapcore.Field {
	return ecsString("file.attributes", value)
}

// Accessed create the ECS compliant 'file.accessed' field.
// Last time the file was accessed. Note that not all filesystems keep
// track of access time.
func (nsFile) Accessed(value time.Time) zapcore.Field {
	return ecsTime("file.accessed", value)
}

// TargetPath create the ECS compliant 'file.target_path' field.
// Target path for symlinks.
func (nsFile) TargetPath(value string) zapcore.Field {
	return ecsString("file.target_path", value)
}

// Mode create the ECS compliant 'file.mode' field.
// Mode of the file in octal representation.
func (nsFile) Mode(value string) zapcore.Field {
	return ecsString("file.mode", value)
}

// Inode create the ECS compliant 'file.inode' field.
// Inode representing the file in the filesystem.
func (nsFile) Inode(value string) zapcore.Field {
	return ecsString("file.inode", value)
}

// ## file.code_signature fields

// SubjectName create the ECS compliant 'file.code_signature.subject_name' field.
// Subject name of the code signer
func (nsFileCodeSignature) SubjectName(value string) zapcore.Field {
	return ecsString("file.code_signature.subject_name", value)
}

// Status create the ECS compliant 'file.code_signature.status' field.
// Additional information about the certificate status. This is useful for
// logging cryptographic errors with the certificate validity or trust
// status. Leave unpopulated if the validity or trust of the certificate
// was unchecked.
func (nsFileCodeSignature) Status(value string) zapcore.Field {
	return ecsString("file.code_signature.status", value)
}

// Exists create the ECS compliant 'file.code_signature.exists' field.
// Boolean to capture if a signature is present.
func (nsFileCodeSignature) Exists(value bool) zapcore.Field {
	return ecsBool("file.code_signature.exists", value)
}

// Trusted create the ECS compliant 'file.code_signature.trusted' field.
// Stores the trust status of the certificate chain. Validating the trust
// of the certificate chain may be complicated, and this field should only
// be populated by tools that actively check the status.
func (nsFileCodeSignature) Trusted(value bool) zapcore.Field {
	return ecsBool("file.code_signature.trusted", value)
}

// Valid create the ECS compliant 'file.code_signature.valid' field.
// Boolean to capture if the digital signature is verified against the
// binary content. Leave unpopulated if a certificate was unchecked.
func (nsFileCodeSignature) Valid(value bool) zapcore.Field {
	return ecsBool("file.code_signature.valid", value)
}

// ## file.hash fields

// Sha256 create the ECS compliant 'file.hash.sha256' field.
// SHA256 hash.
func (nsFileHash) Sha256(value string) zapcore.Field {
	return ecsString("file.hash.sha256", value)
}

// Sha1 create the ECS compliant 'file.hash.sha1' field.
// SHA1 hash.
func (nsFileHash) Sha1(value string) zapcore.Field {
	return ecsString("file.hash.sha1", value)
}

// Md5 create the ECS compliant 'file.hash.md5' field.
// MD5 hash.
func (nsFileHash) Md5(value string) zapcore.Field {
	return ecsString("file.hash.md5", value)
}

// Sha512 create the ECS compliant 'file.hash.sha512' field.
// SHA512 hash.
func (nsFileHash) Sha512(value string) zapcore.Field {
	return ecsString("file.hash.sha512", value)
}

// ## file.pe fields

// OriginalFileName create the ECS compliant 'file.pe.original_file_name' field.
// Internal name of the file, provided at compile-time.
func (nsFilePe) OriginalFileName(value string) zapcore.Field {
	return ecsString("file.pe.original_file_name", value)
}

// FileVersion create the ECS compliant 'file.pe.file_version' field.
// Internal version of the file, provided at compile-time.
func (nsFilePe) FileVersion(value string) zapcore.Field {
	return ecsString("file.pe.file_version", value)
}

// Product create the ECS compliant 'file.pe.product' field.
// Internal product name of the file, provided at compile-time.
func (nsFilePe) Product(value string) zapcore.Field {
	return ecsString("file.pe.product", value)
}

// Company create the ECS compliant 'file.pe.company' field.
// Internal company name of the file, provided at compile-time.
func (nsFilePe) Company(value string) zapcore.Field {
	return ecsString("file.pe.company", value)
}

// Description create the ECS compliant 'file.pe.description' field.
// Internal description of the file, provided at compile-time.
func (nsFilePe) Description(value string) zapcore.Field {
	return ecsString("file.pe.description", value)
}

// ## geo fields

// ContinentName create the ECS compliant 'geo.continent_name' field.
// Name of the continent.
func (nsGeo) ContinentName(value string) zapcore.Field {
	return ecsString("geo.continent_name", value)
}

// CountryName create the ECS compliant 'geo.country_name' field.
// Country name.
func (nsGeo) CountryName(value string) zapcore.Field {
	return ecsString("geo.country_name", value)
}

// Name create the ECS compliant 'geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (nsGeo) Name(value string) zapcore.Field {
	return ecsString("geo.name", value)
}

// Location create the ECS compliant 'geo.location' field.
// Longitude and latitude.
func (nsGeo) Location(value string) zapcore.Field {
	return ecsString("geo.location", value)
}

// RegionName create the ECS compliant 'geo.region_name' field.
// Region name.
func (nsGeo) RegionName(value string) zapcore.Field {
	return ecsString("geo.region_name", value)
}

// RegionIsoCode create the ECS compliant 'geo.region_iso_code' field.
// Region ISO code.
func (nsGeo) RegionIsoCode(value string) zapcore.Field {
	return ecsString("geo.region_iso_code", value)
}

// CountryIsoCode create the ECS compliant 'geo.country_iso_code' field.
// Country ISO code.
func (nsGeo) CountryIsoCode(value string) zapcore.Field {
	return ecsString("geo.country_iso_code", value)
}

// CityName create the ECS compliant 'geo.city_name' field.
// City name.
func (nsGeo) CityName(value string) zapcore.Field {
	return ecsString("geo.city_name", value)
}

// ## group fields

// ID create the ECS compliant 'group.id' field.
// Unique identifier for the group on the system/platform.
func (nsGroup) ID(value string) zapcore.Field {
	return ecsString("group.id", value)
}

// Domain create the ECS compliant 'group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsGroup) Domain(value string) zapcore.Field {
	return ecsString("group.domain", value)
}

// Name create the ECS compliant 'group.name' field.
// Name of the group.
func (nsGroup) Name(value string) zapcore.Field {
	return ecsString("group.name", value)
}

// ## hash fields

// Sha256 create the ECS compliant 'hash.sha256' field.
// SHA256 hash.
func (nsHash) Sha256(value string) zapcore.Field {
	return ecsString("hash.sha256", value)
}

// Sha512 create the ECS compliant 'hash.sha512' field.
// SHA512 hash.
func (nsHash) Sha512(value string) zapcore.Field {
	return ecsString("hash.sha512", value)
}

// Md5 create the ECS compliant 'hash.md5' field.
// MD5 hash.
func (nsHash) Md5(value string) zapcore.Field {
	return ecsString("hash.md5", value)
}

// Sha1 create the ECS compliant 'hash.sha1' field.
// SHA1 hash.
func (nsHash) Sha1(value string) zapcore.Field {
	return ecsString("hash.sha1", value)
}

// ## host fields

// Architecture create the ECS compliant 'host.architecture' field.
// Operating system architecture.
func (nsHost) Architecture(value string) zapcore.Field {
	return ecsString("host.architecture", value)
}

// Domain create the ECS compliant 'host.domain' field.
// Name of the domain of which the host is a member. For example, on
// Windows this could be the host's Active Directory domain or NetBIOS
// domain name. For Linux this could be the domain of the host's LDAP
// provider.
func (nsHost) Domain(value string) zapcore.Field {
	return ecsString("host.domain", value)
}

// ID create the ECS compliant 'host.id' field.
// Unique host id. As hostname is not always unique, use values that are
// meaningful in your environment. Example: The current usage of
// `beat.name`.
func (nsHost) ID(value string) zapcore.Field {
	return ecsString("host.id", value)
}

// Name create the ECS compliant 'host.name' field.
// Name of the host. It can contain what `hostname` returns on Unix
// systems, the fully qualified domain name, or a name specified by the
// user. The sender decides which value to use.
func (nsHost) Name(value string) zapcore.Field {
	return ecsString("host.name", value)
}

// IP create the ECS compliant 'host.ip' field.
// Host ip addresses.
func (nsHost) IP(value string) zapcore.Field {
	return ecsString("host.ip", value)
}

// Hostname create the ECS compliant 'host.hostname' field.
// Hostname of the host. It normally contains what the `hostname` command
// returns on the host machine.
func (nsHost) Hostname(value string) zapcore.Field {
	return ecsString("host.hostname", value)
}

// MAC create the ECS compliant 'host.mac' field.
// Host mac addresses.
func (nsHost) MAC(value string) zapcore.Field {
	return ecsString("host.mac", value)
}

// Type create the ECS compliant 'host.type' field.
// Type of host. For Cloud providers this can be the machine type like
// `t2.medium`. If vm, this could be the container, for example, or other
// information meaningful in your environment.
func (nsHost) Type(value string) zapcore.Field {
	return ecsString("host.type", value)
}

// Uptime create the ECS compliant 'host.uptime' field.
// Seconds the host has been up.
func (nsHost) Uptime(value int64) zapcore.Field {
	return ecsInt64("host.uptime", value)
}

// ## host.geo fields

// CityName create the ECS compliant 'host.geo.city_name' field.
// City name.
func (nsHostGeo) CityName(value string) zapcore.Field {
	return ecsString("host.geo.city_name", value)
}

// Location create the ECS compliant 'host.geo.location' field.
// Longitude and latitude.
func (nsHostGeo) Location(value string) zapcore.Field {
	return ecsString("host.geo.location", value)
}

// CountryName create the ECS compliant 'host.geo.country_name' field.
// Country name.
func (nsHostGeo) CountryName(value string) zapcore.Field {
	return ecsString("host.geo.country_name", value)
}

// RegionName create the ECS compliant 'host.geo.region_name' field.
// Region name.
func (nsHostGeo) RegionName(value string) zapcore.Field {
	return ecsString("host.geo.region_name", value)
}

// CountryIsoCode create the ECS compliant 'host.geo.country_iso_code' field.
// Country ISO code.
func (nsHostGeo) CountryIsoCode(value string) zapcore.Field {
	return ecsString("host.geo.country_iso_code", value)
}

// Name create the ECS compliant 'host.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (nsHostGeo) Name(value string) zapcore.Field {
	return ecsString("host.geo.name", value)
}

// ContinentName create the ECS compliant 'host.geo.continent_name' field.
// Name of the continent.
func (nsHostGeo) ContinentName(value string) zapcore.Field {
	return ecsString("host.geo.continent_name", value)
}

// RegionIsoCode create the ECS compliant 'host.geo.region_iso_code' field.
// Region ISO code.
func (nsHostGeo) RegionIsoCode(value string) zapcore.Field {
	return ecsString("host.geo.region_iso_code", value)
}

// ## host.os fields

// Platform create the ECS compliant 'host.os.platform' field.
// Operating system platform (such centos, ubuntu, windows).
func (nsHostOS) Platform(value string) zapcore.Field {
	return ecsString("host.os.platform", value)
}

// Kernel create the ECS compliant 'host.os.kernel' field.
// Operating system kernel version as a raw string.
func (nsHostOS) Kernel(value string) zapcore.Field {
	return ecsString("host.os.kernel", value)
}

// Full create the ECS compliant 'host.os.full' field.
// Operating system name, including the version or code name.
func (nsHostOS) Full(value string) zapcore.Field {
	return ecsString("host.os.full", value)
}

// Version create the ECS compliant 'host.os.version' field.
// Operating system version as a raw string.
func (nsHostOS) Version(value string) zapcore.Field {
	return ecsString("host.os.version", value)
}

// Name create the ECS compliant 'host.os.name' field.
// Operating system name, without the version.
func (nsHostOS) Name(value string) zapcore.Field {
	return ecsString("host.os.name", value)
}

// Family create the ECS compliant 'host.os.family' field.
// OS family (such as redhat, debian, freebsd, windows).
func (nsHostOS) Family(value string) zapcore.Field {
	return ecsString("host.os.family", value)
}

// ## host.user fields

// Name create the ECS compliant 'host.user.name' field.
// Short name or login of the user.
func (nsHostUser) Name(value string) zapcore.Field {
	return ecsString("host.user.name", value)
}

// Hash create the ECS compliant 'host.user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (nsHostUser) Hash(value string) zapcore.Field {
	return ecsString("host.user.hash", value)
}

// Email create the ECS compliant 'host.user.email' field.
// User email address.
func (nsHostUser) Email(value string) zapcore.Field {
	return ecsString("host.user.email", value)
}

// FullName create the ECS compliant 'host.user.full_name' field.
// User's full name, if available.
func (nsHostUser) FullName(value string) zapcore.Field {
	return ecsString("host.user.full_name", value)
}

// Domain create the ECS compliant 'host.user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsHostUser) Domain(value string) zapcore.Field {
	return ecsString("host.user.domain", value)
}

// ID create the ECS compliant 'host.user.id' field.
// Unique identifiers of the user.
func (nsHostUser) ID(value string) zapcore.Field {
	return ecsString("host.user.id", value)
}

// ## host.user.group fields

// Domain create the ECS compliant 'host.user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsHostUserGroup) Domain(value string) zapcore.Field {
	return ecsString("host.user.group.domain", value)
}

// Name create the ECS compliant 'host.user.group.name' field.
// Name of the group.
func (nsHostUserGroup) Name(value string) zapcore.Field {
	return ecsString("host.user.group.name", value)
}

// ID create the ECS compliant 'host.user.group.id' field.
// Unique identifier for the group on the system/platform.
func (nsHostUserGroup) ID(value string) zapcore.Field {
	return ecsString("host.user.group.id", value)
}

// ## http fields

// Version create the ECS compliant 'http.version' field.
// HTTP version.
func (nsHTTP) Version(value string) zapcore.Field {
	return ecsString("http.version", value)
}

// ## http.request fields

// Referrer create the ECS compliant 'http.request.referrer' field.
// Referrer for this HTTP request.
func (nsHTTPRequest) Referrer(value string) zapcore.Field {
	return ecsString("http.request.referrer", value)
}

// Bytes create the ECS compliant 'http.request.bytes' field.
// Total size in bytes of the request (body and headers).
func (nsHTTPRequest) Bytes(value int64) zapcore.Field {
	return ecsInt64("http.request.bytes", value)
}

// Method create the ECS compliant 'http.request.method' field.
// HTTP request method. The field value must be normalized to lowercase
// for querying. See the documentation section "Implementing ECS".
func (nsHTTPRequest) Method(value string) zapcore.Field {
	return ecsString("http.request.method", value)
}

// ## http.request.body fields

// Content create the ECS compliant 'http.request.body.content' field.
// The full HTTP request body.
func (nsHTTPRequestBody) Content(value string) zapcore.Field {
	return ecsString("http.request.body.content", value)
}

// Bytes create the ECS compliant 'http.request.body.bytes' field.
// Size in bytes of the request body.
func (nsHTTPRequestBody) Bytes(value int64) zapcore.Field {
	return ecsInt64("http.request.body.bytes", value)
}

// ## http.response fields

// StatusCode create the ECS compliant 'http.response.status_code' field.
// HTTP response status code.
func (nsHTTPResponse) StatusCode(value int64) zapcore.Field {
	return ecsInt64("http.response.status_code", value)
}

// Bytes create the ECS compliant 'http.response.bytes' field.
// Total size in bytes of the response (body and headers).
func (nsHTTPResponse) Bytes(value int64) zapcore.Field {
	return ecsInt64("http.response.bytes", value)
}

// ## http.response.body fields

// Bytes create the ECS compliant 'http.response.body.bytes' field.
// Size in bytes of the response body.
func (nsHTTPResponseBody) Bytes(value int64) zapcore.Field {
	return ecsInt64("http.response.body.bytes", value)
}

// Content create the ECS compliant 'http.response.body.content' field.
// The full HTTP response body.
func (nsHTTPResponseBody) Content(value string) zapcore.Field {
	return ecsString("http.response.body.content", value)
}

// ## interface fields

// Alias create the ECS compliant 'interface.alias' field.
// Interface alias as reported by the system, typically used in firewall
// implementations for e.g. inside, outside, or dmz logical interface
// naming.
func (nsInterface) Alias(value string) zapcore.Field {
	return ecsString("interface.alias", value)
}

// Name create the ECS compliant 'interface.name' field.
// Interface name as reported by the system.
func (nsInterface) Name(value string) zapcore.Field {
	return ecsString("interface.name", value)
}

// ID create the ECS compliant 'interface.id' field.
// Interface ID as reported by an observer (typically SNMP interface ID).
func (nsInterface) ID(value string) zapcore.Field {
	return ecsString("interface.id", value)
}

// ## log fields

// Level create the ECS compliant 'log.level' field.
// Original log level of the log event. If the source of the event
// provides a log level or textual severity, this is the one that goes in
// `log.level`. If your source doesn't specify one, you may put your event
// transport's severity here (e.g. Syslog severity). Some examples are
// `warn`, `err`, `i`, `informational`.
func (nsLog) Level(value string) zapcore.Field {
	return ecsString("log.level", value)
}

// Logger create the ECS compliant 'log.logger' field.
// The name of the logger inside an application. This is usually the name
// of the class which initialized the logger, or can be a custom name.
func (nsLog) Logger(value string) zapcore.Field {
	return ecsString("log.logger", value)
}

// Original create the ECS compliant 'log.original' field.
// This is the original log message and contains the full log message
// before splitting it up in multiple parts. In contrast to the `message`
// field which can contain an extracted part of the log message, this
// field contains the original, full log message. It can have already some
// modifications applied like encoding or new lines removed to clean up
// the log message. This field is not indexed and doc_values are disabled
// so it can't be queried but the value can be retrieved from `_source`.
func (nsLog) Original(value string) zapcore.Field {
	return ecsString("log.original", value)
}

// ## log.origin fields

// Function create the ECS compliant 'log.origin.function' field.
// The name of the function or method which originated the log event.
func (nsLogOrigin) Function(value string) zapcore.Field {
	return ecsString("log.origin.function", value)
}

// ## log.origin.file fields

// Name create the ECS compliant 'log.origin.file.name' field.
// The name of the file containing the source code which originated the
// log event. Note that this is not the name of the log file.
func (nsLogOriginFile) Name(value string) zapcore.Field {
	return ecsString("log.origin.file.name", value)
}

// Line create the ECS compliant 'log.origin.file.line' field.
// The line number of the file containing the source code which originated
// the log event.
func (nsLogOriginFile) Line(value int) zapcore.Field {
	return ecsInt("log.origin.file.line", value)
}

// ## log.syslog fields

// Priority create the ECS compliant 'log.syslog.priority' field.
// Syslog numeric priority of the event, if available. According to RFCs
// 5424 and 3164, the priority is 8 * facility + severity. This number is
// therefore expected to contain a value between 0 and 191.
func (nsLogSyslog) Priority(value int64) zapcore.Field {
	return ecsInt64("log.syslog.priority", value)
}

// ## log.syslog.facility fields

// Name create the ECS compliant 'log.syslog.facility.name' field.
// The Syslog text-based facility of the log event, if available.
func (nsLogSyslogFacility) Name(value string) zapcore.Field {
	return ecsString("log.syslog.facility.name", value)
}

// Code create the ECS compliant 'log.syslog.facility.code' field.
// The Syslog numeric facility of the log event, if available. According
// to RFCs 5424 and 3164, this value should be an integer between 0 and
// 23.
func (nsLogSyslogFacility) Code(value int64) zapcore.Field {
	return ecsInt64("log.syslog.facility.code", value)
}

// ## log.syslog.severity fields

// Code create the ECS compliant 'log.syslog.severity.code' field.
// The Syslog numeric severity of the log event, if available. If the
// event source publishing via Syslog provides a different numeric
// severity value (e.g. firewall, IDS), your source's numeric severity
// should go to `event.severity`. If the event source does not specify a
// distinct severity, you can optionally copy the Syslog severity to
// `event.severity`.
func (nsLogSyslogSeverity) Code(value int64) zapcore.Field {
	return ecsInt64("log.syslog.severity.code", value)
}

// Name create the ECS compliant 'log.syslog.severity.name' field.
// The Syslog numeric severity of the log event, if available. If the
// event source publishing via Syslog provides a different severity value
// (e.g. firewall, IDS), your source's text severity should go to
// `log.level`. If the event source does not specify a distinct severity,
// you can optionally copy the Syslog severity to `log.level`.
func (nsLogSyslogSeverity) Name(value string) zapcore.Field {
	return ecsString("log.syslog.severity.name", value)
}

// ## network fields

// Bytes create the ECS compliant 'network.bytes' field.
// Total bytes transferred in both directions. If `source.bytes` and
// `destination.bytes` are known, `network.bytes` is their sum.
func (nsNetwork) Bytes(value int64) zapcore.Field {
	return ecsInt64("network.bytes", value)
}

// Application create the ECS compliant 'network.application' field.
// A name given to an application level protocol. This can be arbitrarily
// assigned for things like microservices, but also apply to things like
// skype, icq, facebook, twitter. This would be used in situations where
// the vendor or service can be decoded such as from the source/dest IP
// owners, ports, or wire format. The field value must be normalized to
// lowercase for querying. See the documentation section "Implementing
// ECS".
func (nsNetwork) Application(value string) zapcore.Field {
	return ecsString("network.application", value)
}

// Transport create the ECS compliant 'network.transport' field.
// Same as network.iana_number, but instead using the Keyword name of the
// transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be
// normalized to lowercase for querying. See the documentation section
// "Implementing ECS".
func (nsNetwork) Transport(value string) zapcore.Field {
	return ecsString("network.transport", value)
}

// Packets create the ECS compliant 'network.packets' field.
// Total packets transferred in both directions. If `source.packets` and
// `destination.packets` are known, `network.packets` is their sum.
func (nsNetwork) Packets(value int64) zapcore.Field {
	return ecsInt64("network.packets", value)
}

// CommunityID create the ECS compliant 'network.community_id' field.
// A hash of source and destination IPs and ports, as well as the protocol
// used in a communication. This is a tool-agnostic standard to identify
// flows. Learn more at https://github.com/corelight/community-id-spec.
func (nsNetwork) CommunityID(value string) zapcore.Field {
	return ecsString("network.community_id", value)
}

// Protocol create the ECS compliant 'network.protocol' field.
// L7 Network protocol name. ex. http, lumberjack, transport protocol. The
// field value must be normalized to lowercase for querying. See the
// documentation section "Implementing ECS".
func (nsNetwork) Protocol(value string) zapcore.Field {
	return ecsString("network.protocol", value)
}

// IANANumber create the ECS compliant 'network.iana_number' field.
// IANA Protocol Number
// (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).
// Standardized list of protocols. This aligns well with NetFlow and sFlow
// related logs which use the IANA Protocol Number.
func (nsNetwork) IANANumber(value string) zapcore.Field {
	return ecsString("network.iana_number", value)
}

// Direction create the ECS compliant 'network.direction' field.
// Direction of the network traffic. Recommended values are:   * inbound
// * outbound   * internal   * external   * unknown  When mapping events
// from a host-based monitoring context, populate this field from the
// host's point of view. When mapping events from a network or
// perimeter-based monitoring context, populate this field from the point
// of view of your network perimeter.
func (nsNetwork) Direction(value string) zapcore.Field {
	return ecsString("network.direction", value)
}

// Type create the ECS compliant 'network.type' field.
// In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec,
// pim, etc The field value must be normalized to lowercase for querying.
// See the documentation section "Implementing ECS".
func (nsNetwork) Type(value string) zapcore.Field {
	return ecsString("network.type", value)
}

// ForwardedIP create the ECS compliant 'network.forwarded_ip' field.
// Host IP address when the source IP address is the proxy.
func (nsNetwork) ForwardedIP(value string) zapcore.Field {
	return ecsString("network.forwarded_ip", value)
}

// Name create the ECS compliant 'network.name' field.
// Name given by operators to sections of their network.
func (nsNetwork) Name(value string) zapcore.Field {
	return ecsString("network.name", value)
}

// ## network.inner fields

// ## network.inner.vlan fields

// ID create the ECS compliant 'network.inner.vlan.id' field.
// VLAN ID as reported by the observer.
func (nsNetworkInnerVlan) ID(value string) zapcore.Field {
	return ecsString("network.inner.vlan.id", value)
}

// Name create the ECS compliant 'network.inner.vlan.name' field.
// Optional VLAN name as reported by the observer.
func (nsNetworkInnerVlan) Name(value string) zapcore.Field {
	return ecsString("network.inner.vlan.name", value)
}

// ## network.vlan fields

// Name create the ECS compliant 'network.vlan.name' field.
// Optional VLAN name as reported by the observer.
func (nsNetworkVlan) Name(value string) zapcore.Field {
	return ecsString("network.vlan.name", value)
}

// ID create the ECS compliant 'network.vlan.id' field.
// VLAN ID as reported by the observer.
func (nsNetworkVlan) ID(value string) zapcore.Field {
	return ecsString("network.vlan.id", value)
}

// ## observer fields

// IP create the ECS compliant 'observer.ip' field.
// IP addresses of the observer.
func (nsObserver) IP(value string) zapcore.Field {
	return ecsString("observer.ip", value)
}

// Type create the ECS compliant 'observer.type' field.
// The type of the observer the data is coming from. There is no
// predefined list of observer types. Some examples are `forwarder`,
// `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`.
func (nsObserver) Type(value string) zapcore.Field {
	return ecsString("observer.type", value)
}

// MAC create the ECS compliant 'observer.mac' field.
// MAC addresses of the observer
func (nsObserver) MAC(value string) zapcore.Field {
	return ecsString("observer.mac", value)
}

// Hostname create the ECS compliant 'observer.hostname' field.
// Hostname of the observer.
func (nsObserver) Hostname(value string) zapcore.Field {
	return ecsString("observer.hostname", value)
}

// SerialNumber create the ECS compliant 'observer.serial_number' field.
// Observer serial number.
func (nsObserver) SerialNumber(value string) zapcore.Field {
	return ecsString("observer.serial_number", value)
}

// Product create the ECS compliant 'observer.product' field.
// The product name of the observer.
func (nsObserver) Product(value string) zapcore.Field {
	return ecsString("observer.product", value)
}

// Name create the ECS compliant 'observer.name' field.
// Custom name of the observer. This is a name that can be given to an
// observer. This can be helpful for example if multiple firewalls of the
// same model are used in an organization. If no custom name is needed,
// the field can be left empty.
func (nsObserver) Name(value string) zapcore.Field {
	return ecsString("observer.name", value)
}

// Vendor create the ECS compliant 'observer.vendor' field.
// Vendor name of the observer.
func (nsObserver) Vendor(value string) zapcore.Field {
	return ecsString("observer.vendor", value)
}

// Version create the ECS compliant 'observer.version' field.
// Observer version.
func (nsObserver) Version(value string) zapcore.Field {
	return ecsString("observer.version", value)
}

// ## observer.egress fields

// Zone create the ECS compliant 'observer.egress.zone' field.
// Network zone of outbound traffic as reported by the observer to
// categorize the destination area of egress  traffic, e.g. Internal,
// External, DMZ, HR, Legal, etc.
func (nsObserverEgress) Zone(value string) zapcore.Field {
	return ecsString("observer.egress.zone", value)
}

// ## observer.egress.interface fields

// Alias create the ECS compliant 'observer.egress.interface.alias' field.
// Interface alias as reported by the system, typically used in firewall
// implementations for e.g. inside, outside, or dmz logical interface
// naming.
func (nsObserverEgressInterface) Alias(value string) zapcore.Field {
	return ecsString("observer.egress.interface.alias", value)
}

// Name create the ECS compliant 'observer.egress.interface.name' field.
// Interface name as reported by the system.
func (nsObserverEgressInterface) Name(value string) zapcore.Field {
	return ecsString("observer.egress.interface.name", value)
}

// ID create the ECS compliant 'observer.egress.interface.id' field.
// Interface ID as reported by an observer (typically SNMP interface ID).
func (nsObserverEgressInterface) ID(value string) zapcore.Field {
	return ecsString("observer.egress.interface.id", value)
}

// ## observer.egress.vlan fields

// ID create the ECS compliant 'observer.egress.vlan.id' field.
// VLAN ID as reported by the observer.
func (nsObserverEgressVlan) ID(value string) zapcore.Field {
	return ecsString("observer.egress.vlan.id", value)
}

// Name create the ECS compliant 'observer.egress.vlan.name' field.
// Optional VLAN name as reported by the observer.
func (nsObserverEgressVlan) Name(value string) zapcore.Field {
	return ecsString("observer.egress.vlan.name", value)
}

// ## observer.geo fields

// RegionName create the ECS compliant 'observer.geo.region_name' field.
// Region name.
func (nsObserverGeo) RegionName(value string) zapcore.Field {
	return ecsString("observer.geo.region_name", value)
}

// Name create the ECS compliant 'observer.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (nsObserverGeo) Name(value string) zapcore.Field {
	return ecsString("observer.geo.name", value)
}

// ContinentName create the ECS compliant 'observer.geo.continent_name' field.
// Name of the continent.
func (nsObserverGeo) ContinentName(value string) zapcore.Field {
	return ecsString("observer.geo.continent_name", value)
}

// Location create the ECS compliant 'observer.geo.location' field.
// Longitude and latitude.
func (nsObserverGeo) Location(value string) zapcore.Field {
	return ecsString("observer.geo.location", value)
}

// CountryIsoCode create the ECS compliant 'observer.geo.country_iso_code' field.
// Country ISO code.
func (nsObserverGeo) CountryIsoCode(value string) zapcore.Field {
	return ecsString("observer.geo.country_iso_code", value)
}

// RegionIsoCode create the ECS compliant 'observer.geo.region_iso_code' field.
// Region ISO code.
func (nsObserverGeo) RegionIsoCode(value string) zapcore.Field {
	return ecsString("observer.geo.region_iso_code", value)
}

// CountryName create the ECS compliant 'observer.geo.country_name' field.
// Country name.
func (nsObserverGeo) CountryName(value string) zapcore.Field {
	return ecsString("observer.geo.country_name", value)
}

// CityName create the ECS compliant 'observer.geo.city_name' field.
// City name.
func (nsObserverGeo) CityName(value string) zapcore.Field {
	return ecsString("observer.geo.city_name", value)
}

// ## observer.ingress fields

// Zone create the ECS compliant 'observer.ingress.zone' field.
// Network zone of incoming traffic as reported by the observer to
// categorize the source area of ingress  traffic. e.g. internal,
// External, DMZ, HR, Legal, etc.
func (nsObserverIngress) Zone(value string) zapcore.Field {
	return ecsString("observer.ingress.zone", value)
}

// ## observer.ingress.interface fields

// ID create the ECS compliant 'observer.ingress.interface.id' field.
// Interface ID as reported by an observer (typically SNMP interface ID).
func (nsObserverIngressInterface) ID(value string) zapcore.Field {
	return ecsString("observer.ingress.interface.id", value)
}

// Alias create the ECS compliant 'observer.ingress.interface.alias' field.
// Interface alias as reported by the system, typically used in firewall
// implementations for e.g. inside, outside, or dmz logical interface
// naming.
func (nsObserverIngressInterface) Alias(value string) zapcore.Field {
	return ecsString("observer.ingress.interface.alias", value)
}

// Name create the ECS compliant 'observer.ingress.interface.name' field.
// Interface name as reported by the system.
func (nsObserverIngressInterface) Name(value string) zapcore.Field {
	return ecsString("observer.ingress.interface.name", value)
}

// ## observer.ingress.vlan fields

// Name create the ECS compliant 'observer.ingress.vlan.name' field.
// Optional VLAN name as reported by the observer.
func (nsObserverIngressVlan) Name(value string) zapcore.Field {
	return ecsString("observer.ingress.vlan.name", value)
}

// ID create the ECS compliant 'observer.ingress.vlan.id' field.
// VLAN ID as reported by the observer.
func (nsObserverIngressVlan) ID(value string) zapcore.Field {
	return ecsString("observer.ingress.vlan.id", value)
}

// ## observer.os fields

// Family create the ECS compliant 'observer.os.family' field.
// OS family (such as redhat, debian, freebsd, windows).
func (nsObserverOS) Family(value string) zapcore.Field {
	return ecsString("observer.os.family", value)
}

// Name create the ECS compliant 'observer.os.name' field.
// Operating system name, without the version.
func (nsObserverOS) Name(value string) zapcore.Field {
	return ecsString("observer.os.name", value)
}

// Version create the ECS compliant 'observer.os.version' field.
// Operating system version as a raw string.
func (nsObserverOS) Version(value string) zapcore.Field {
	return ecsString("observer.os.version", value)
}

// Platform create the ECS compliant 'observer.os.platform' field.
// Operating system platform (such centos, ubuntu, windows).
func (nsObserverOS) Platform(value string) zapcore.Field {
	return ecsString("observer.os.platform", value)
}

// Full create the ECS compliant 'observer.os.full' field.
// Operating system name, including the version or code name.
func (nsObserverOS) Full(value string) zapcore.Field {
	return ecsString("observer.os.full", value)
}

// Kernel create the ECS compliant 'observer.os.kernel' field.
// Operating system kernel version as a raw string.
func (nsObserverOS) Kernel(value string) zapcore.Field {
	return ecsString("observer.os.kernel", value)
}

// ## organization fields

// ID create the ECS compliant 'organization.id' field.
// Unique identifier for the organization.
func (nsOrganization) ID(value string) zapcore.Field {
	return ecsString("organization.id", value)
}

// Name create the ECS compliant 'organization.name' field.
// Organization name.
func (nsOrganization) Name(value string) zapcore.Field {
	return ecsString("organization.name", value)
}

// ## os fields

// Platform create the ECS compliant 'os.platform' field.
// Operating system platform (such centos, ubuntu, windows).
func (nsOS) Platform(value string) zapcore.Field {
	return ecsString("os.platform", value)
}

// Name create the ECS compliant 'os.name' field.
// Operating system name, without the version.
func (nsOS) Name(value string) zapcore.Field {
	return ecsString("os.name", value)
}

// Version create the ECS compliant 'os.version' field.
// Operating system version as a raw string.
func (nsOS) Version(value string) zapcore.Field {
	return ecsString("os.version", value)
}

// Family create the ECS compliant 'os.family' field.
// OS family (such as redhat, debian, freebsd, windows).
func (nsOS) Family(value string) zapcore.Field {
	return ecsString("os.family", value)
}

// Full create the ECS compliant 'os.full' field.
// Operating system name, including the version or code name.
func (nsOS) Full(value string) zapcore.Field {
	return ecsString("os.full", value)
}

// Kernel create the ECS compliant 'os.kernel' field.
// Operating system kernel version as a raw string.
func (nsOS) Kernel(value string) zapcore.Field {
	return ecsString("os.kernel", value)
}

// ## package fields

// License create the ECS compliant 'package.license' field.
// License under which the package was released. Use a short name, e.g.
// the license identifier from SPDX License List where possible
// (https://spdx.org/licenses/).
func (nsPackage) License(value string) zapcore.Field {
	return ecsString("package.license", value)
}

// Version create the ECS compliant 'package.version' field.
// Package version
func (nsPackage) Version(value string) zapcore.Field {
	return ecsString("package.version", value)
}

// Checksum create the ECS compliant 'package.checksum' field.
// Checksum of the installed package for verification.
func (nsPackage) Checksum(value string) zapcore.Field {
	return ecsString("package.checksum", value)
}

// Size create the ECS compliant 'package.size' field.
// Package size in bytes.
func (nsPackage) Size(value int64) zapcore.Field {
	return ecsInt64("package.size", value)
}

// Name create the ECS compliant 'package.name' field.
// Package name
func (nsPackage) Name(value string) zapcore.Field {
	return ecsString("package.name", value)
}

// Reference create the ECS compliant 'package.reference' field.
// Home page or reference URL of the software in this package, if
// available.
func (nsPackage) Reference(value string) zapcore.Field {
	return ecsString("package.reference", value)
}

// Type create the ECS compliant 'package.type' field.
// Type of package. This should contain the package file type, rather than
// the package manager name. Examples: rpm, dpkg, brew, npm, gem, nupkg,
// jar.
func (nsPackage) Type(value string) zapcore.Field {
	return ecsString("package.type", value)
}

// Path create the ECS compliant 'package.path' field.
// Path where the package is installed.
func (nsPackage) Path(value string) zapcore.Field {
	return ecsString("package.path", value)
}

// Installed create the ECS compliant 'package.installed' field.
// Time when package was installed.
func (nsPackage) Installed(value time.Time) zapcore.Field {
	return ecsTime("package.installed", value)
}

// BuildVersion create the ECS compliant 'package.build_version' field.
// Additional information about the build version of the installed
// package. For example use the commit SHA of a non-released package.
func (nsPackage) BuildVersion(value string) zapcore.Field {
	return ecsString("package.build_version", value)
}

// Description create the ECS compliant 'package.description' field.
// Description of the package.
func (nsPackage) Description(value string) zapcore.Field {
	return ecsString("package.description", value)
}

// InstallScope create the ECS compliant 'package.install_scope' field.
// Indicating how the package was installed, e.g. user-local, global.
func (nsPackage) InstallScope(value string) zapcore.Field {
	return ecsString("package.install_scope", value)
}

// Architecture create the ECS compliant 'package.architecture' field.
// Package architecture.
func (nsPackage) Architecture(value string) zapcore.Field {
	return ecsString("package.architecture", value)
}

// ## pe fields

// FileVersion create the ECS compliant 'pe.file_version' field.
// Internal version of the file, provided at compile-time.
func (nsPe) FileVersion(value string) zapcore.Field {
	return ecsString("pe.file_version", value)
}

// Description create the ECS compliant 'pe.description' field.
// Internal description of the file, provided at compile-time.
func (nsPe) Description(value string) zapcore.Field {
	return ecsString("pe.description", value)
}

// Company create the ECS compliant 'pe.company' field.
// Internal company name of the file, provided at compile-time.
func (nsPe) Company(value string) zapcore.Field {
	return ecsString("pe.company", value)
}

// OriginalFileName create the ECS compliant 'pe.original_file_name' field.
// Internal name of the file, provided at compile-time.
func (nsPe) OriginalFileName(value string) zapcore.Field {
	return ecsString("pe.original_file_name", value)
}

// Product create the ECS compliant 'pe.product' field.
// Internal product name of the file, provided at compile-time.
func (nsPe) Product(value string) zapcore.Field {
	return ecsString("pe.product", value)
}

// ## process fields

// WorkingDirectory create the ECS compliant 'process.working_directory' field.
// The working directory of the process.
func (nsProcess) WorkingDirectory(value string) zapcore.Field {
	return ecsString("process.working_directory", value)
}

// PPID create the ECS compliant 'process.ppid' field.
// Parent process' pid.
func (nsProcess) PPID(value int64) zapcore.Field {
	return ecsInt64("process.ppid", value)
}

// Pgid create the ECS compliant 'process.pgid' field.
// Identifier of the group of processes the process belongs to.
func (nsProcess) Pgid(value int64) zapcore.Field {
	return ecsInt64("process.pgid", value)
}

// EntityID create the ECS compliant 'process.entity_id' field.
// Unique identifier for the process. The implementation of this is
// specified by the data source, but some examples of what could be used
// here are a process-generated UUID, Sysmon Process GUIDs, or a hash of
// some uniquely identifying components of a process. Constructing a
// globally unique identifier is a common practice to mitigate PID reuse
// as well as to identify a specific process over time, across multiple
// monitored hosts.
func (nsProcess) EntityID(value string) zapcore.Field {
	return ecsString("process.entity_id", value)
}

// Args create the ECS compliant 'process.args' field.
// Array of process arguments, starting with the absolute path to the
// executable. May be filtered to protect sensitive information.
func (nsProcess) Args(value string) zapcore.Field {
	return ecsString("process.args", value)
}

// CommandLine create the ECS compliant 'process.command_line' field.
// Full command line that started the process, including the absolute path
// to the executable, and all arguments. Some arguments may be filtered to
// protect sensitive information.
func (nsProcess) CommandLine(value string) zapcore.Field {
	return ecsString("process.command_line", value)
}

// Uptime create the ECS compliant 'process.uptime' field.
// Seconds the process has been up.
func (nsProcess) Uptime(value int64) zapcore.Field {
	return ecsInt64("process.uptime", value)
}

// Start create the ECS compliant 'process.start' field.
// The time the process started.
func (nsProcess) Start(value time.Time) zapcore.Field {
	return ecsTime("process.start", value)
}

// Executable create the ECS compliant 'process.executable' field.
// Absolute path to the process executable.
func (nsProcess) Executable(value string) zapcore.Field {
	return ecsString("process.executable", value)
}

// ArgsCount create the ECS compliant 'process.args_count' field.
// Length of the process.args array. This field can be useful for querying
// or performing bucket analysis on how many arguments were provided to
// start a process. More arguments may be an indication of suspicious
// activity.
func (nsProcess) ArgsCount(value int64) zapcore.Field {
	return ecsInt64("process.args_count", value)
}

// Title create the ECS compliant 'process.title' field.
// Process title. The proctitle, some times the same as process name. Can
// also be different: for example a browser setting its title to the web
// page currently opened.
func (nsProcess) Title(value string) zapcore.Field {
	return ecsString("process.title", value)
}

// Name create the ECS compliant 'process.name' field.
// Process name. Sometimes called program name or similar.
func (nsProcess) Name(value string) zapcore.Field {
	return ecsString("process.name", value)
}

// PID create the ECS compliant 'process.pid' field.
// Process id.
func (nsProcess) PID(value int64) zapcore.Field {
	return ecsInt64("process.pid", value)
}

// ExitCode create the ECS compliant 'process.exit_code' field.
// The exit code of the process, if this is a termination event. The field
// should be absent if there is no exit code for the event (e.g. process
// start).
func (nsProcess) ExitCode(value int64) zapcore.Field {
	return ecsInt64("process.exit_code", value)
}

// ## process.code_signature fields

// Valid create the ECS compliant 'process.code_signature.valid' field.
// Boolean to capture if the digital signature is verified against the
// binary content. Leave unpopulated if a certificate was unchecked.
func (nsProcessCodeSignature) Valid(value bool) zapcore.Field {
	return ecsBool("process.code_signature.valid", value)
}

// Status create the ECS compliant 'process.code_signature.status' field.
// Additional information about the certificate status. This is useful for
// logging cryptographic errors with the certificate validity or trust
// status. Leave unpopulated if the validity or trust of the certificate
// was unchecked.
func (nsProcessCodeSignature) Status(value string) zapcore.Field {
	return ecsString("process.code_signature.status", value)
}

// Trusted create the ECS compliant 'process.code_signature.trusted' field.
// Stores the trust status of the certificate chain. Validating the trust
// of the certificate chain may be complicated, and this field should only
// be populated by tools that actively check the status.
func (nsProcessCodeSignature) Trusted(value bool) zapcore.Field {
	return ecsBool("process.code_signature.trusted", value)
}

// Exists create the ECS compliant 'process.code_signature.exists' field.
// Boolean to capture if a signature is present.
func (nsProcessCodeSignature) Exists(value bool) zapcore.Field {
	return ecsBool("process.code_signature.exists", value)
}

// SubjectName create the ECS compliant 'process.code_signature.subject_name' field.
// Subject name of the code signer
func (nsProcessCodeSignature) SubjectName(value string) zapcore.Field {
	return ecsString("process.code_signature.subject_name", value)
}

// ## process.hash fields

// Sha512 create the ECS compliant 'process.hash.sha512' field.
// SHA512 hash.
func (nsProcessHash) Sha512(value string) zapcore.Field {
	return ecsString("process.hash.sha512", value)
}

// Sha256 create the ECS compliant 'process.hash.sha256' field.
// SHA256 hash.
func (nsProcessHash) Sha256(value string) zapcore.Field {
	return ecsString("process.hash.sha256", value)
}

// Md5 create the ECS compliant 'process.hash.md5' field.
// MD5 hash.
func (nsProcessHash) Md5(value string) zapcore.Field {
	return ecsString("process.hash.md5", value)
}

// Sha1 create the ECS compliant 'process.hash.sha1' field.
// SHA1 hash.
func (nsProcessHash) Sha1(value string) zapcore.Field {
	return ecsString("process.hash.sha1", value)
}

// ## process.parent fields

// EntityID create the ECS compliant 'process.parent.entity_id' field.
// Unique identifier for the process. The implementation of this is
// specified by the data source, but some examples of what could be used
// here are a process-generated UUID, Sysmon Process GUIDs, or a hash of
// some uniquely identifying components of a process. Constructing a
// globally unique identifier is a common practice to mitigate PID reuse
// as well as to identify a specific process over time, across multiple
// monitored hosts.
func (nsProcessParent) EntityID(value string) zapcore.Field {
	return ecsString("process.parent.entity_id", value)
}

// ExitCode create the ECS compliant 'process.parent.exit_code' field.
// The exit code of the process, if this is a termination event. The field
// should be absent if there is no exit code for the event (e.g. process
// start).
func (nsProcessParent) ExitCode(value int64) zapcore.Field {
	return ecsInt64("process.parent.exit_code", value)
}

// Uptime create the ECS compliant 'process.parent.uptime' field.
// Seconds the process has been up.
func (nsProcessParent) Uptime(value int64) zapcore.Field {
	return ecsInt64("process.parent.uptime", value)
}

// Title create the ECS compliant 'process.parent.title' field.
// Process title. The proctitle, some times the same as process name. Can
// also be different: for example a browser setting its title to the web
// page currently opened.
func (nsProcessParent) Title(value string) zapcore.Field {
	return ecsString("process.parent.title", value)
}

// Start create the ECS compliant 'process.parent.start' field.
// The time the process started.
func (nsProcessParent) Start(value time.Time) zapcore.Field {
	return ecsTime("process.parent.start", value)
}

// Args create the ECS compliant 'process.parent.args' field.
// Array of process arguments. May be filtered to protect sensitive
// information.
func (nsProcessParent) Args(value string) zapcore.Field {
	return ecsString("process.parent.args", value)
}

// ArgsCount create the ECS compliant 'process.parent.args_count' field.
// Length of the process.args array. This field can be useful for querying
// or performing bucket analysis on how many arguments were provided to
// start a process. More arguments may be an indication of suspicious
// activity.
func (nsProcessParent) ArgsCount(value int64) zapcore.Field {
	return ecsInt64("process.parent.args_count", value)
}

// Pgid create the ECS compliant 'process.parent.pgid' field.
// Identifier of the group of processes the process belongs to.
func (nsProcessParent) Pgid(value int64) zapcore.Field {
	return ecsInt64("process.parent.pgid", value)
}

// PPID create the ECS compliant 'process.parent.ppid' field.
// Parent process' pid.
func (nsProcessParent) PPID(value int64) zapcore.Field {
	return ecsInt64("process.parent.ppid", value)
}

// CommandLine create the ECS compliant 'process.parent.command_line' field.
// Full command line that started the process, including the absolute path
// to the executable, and all arguments. Some arguments may be filtered to
// protect sensitive information.
func (nsProcessParent) CommandLine(value string) zapcore.Field {
	return ecsString("process.parent.command_line", value)
}

// Name create the ECS compliant 'process.parent.name' field.
// Process name. Sometimes called program name or similar.
func (nsProcessParent) Name(value string) zapcore.Field {
	return ecsString("process.parent.name", value)
}

// Executable create the ECS compliant 'process.parent.executable' field.
// Absolute path to the process executable.
func (nsProcessParent) Executable(value string) zapcore.Field {
	return ecsString("process.parent.executable", value)
}

// PID create the ECS compliant 'process.parent.pid' field.
// Process id.
func (nsProcessParent) PID(value int64) zapcore.Field {
	return ecsInt64("process.parent.pid", value)
}

// WorkingDirectory create the ECS compliant 'process.parent.working_directory' field.
// The working directory of the process.
func (nsProcessParent) WorkingDirectory(value string) zapcore.Field {
	return ecsString("process.parent.working_directory", value)
}

// ## process.parent.code_signature fields

// Exists create the ECS compliant 'process.parent.code_signature.exists' field.
// Boolean to capture if a signature is present.
func (nsProcessParentCodeSignature) Exists(value bool) zapcore.Field {
	return ecsBool("process.parent.code_signature.exists", value)
}

// Trusted create the ECS compliant 'process.parent.code_signature.trusted' field.
// Stores the trust status of the certificate chain. Validating the trust
// of the certificate chain may be complicated, and this field should only
// be populated by tools that actively check the status.
func (nsProcessParentCodeSignature) Trusted(value bool) zapcore.Field {
	return ecsBool("process.parent.code_signature.trusted", value)
}

// Status create the ECS compliant 'process.parent.code_signature.status' field.
// Additional information about the certificate status. This is useful for
// logging cryptographic errors with the certificate validity or trust
// status. Leave unpopulated if the validity or trust of the certificate
// was unchecked.
func (nsProcessParentCodeSignature) Status(value string) zapcore.Field {
	return ecsString("process.parent.code_signature.status", value)
}

// SubjectName create the ECS compliant 'process.parent.code_signature.subject_name' field.
// Subject name of the code signer
func (nsProcessParentCodeSignature) SubjectName(value string) zapcore.Field {
	return ecsString("process.parent.code_signature.subject_name", value)
}

// Valid create the ECS compliant 'process.parent.code_signature.valid' field.
// Boolean to capture if the digital signature is verified against the
// binary content. Leave unpopulated if a certificate was unchecked.
func (nsProcessParentCodeSignature) Valid(value bool) zapcore.Field {
	return ecsBool("process.parent.code_signature.valid", value)
}

// ## process.parent.hash fields

// Sha256 create the ECS compliant 'process.parent.hash.sha256' field.
// SHA256 hash.
func (nsProcessParentHash) Sha256(value string) zapcore.Field {
	return ecsString("process.parent.hash.sha256", value)
}

// Sha1 create the ECS compliant 'process.parent.hash.sha1' field.
// SHA1 hash.
func (nsProcessParentHash) Sha1(value string) zapcore.Field {
	return ecsString("process.parent.hash.sha1", value)
}

// Md5 create the ECS compliant 'process.parent.hash.md5' field.
// MD5 hash.
func (nsProcessParentHash) Md5(value string) zapcore.Field {
	return ecsString("process.parent.hash.md5", value)
}

// Sha512 create the ECS compliant 'process.parent.hash.sha512' field.
// SHA512 hash.
func (nsProcessParentHash) Sha512(value string) zapcore.Field {
	return ecsString("process.parent.hash.sha512", value)
}

// ## process.parent.thread fields

// ID create the ECS compliant 'process.parent.thread.id' field.
// Thread ID.
func (nsProcessParentThread) ID(value int64) zapcore.Field {
	return ecsInt64("process.parent.thread.id", value)
}

// Name create the ECS compliant 'process.parent.thread.name' field.
// Thread name.
func (nsProcessParentThread) Name(value string) zapcore.Field {
	return ecsString("process.parent.thread.name", value)
}

// ## process.pe fields

// OriginalFileName create the ECS compliant 'process.pe.original_file_name' field.
// Internal name of the file, provided at compile-time.
func (nsProcessPe) OriginalFileName(value string) zapcore.Field {
	return ecsString("process.pe.original_file_name", value)
}

// Description create the ECS compliant 'process.pe.description' field.
// Internal description of the file, provided at compile-time.
func (nsProcessPe) Description(value string) zapcore.Field {
	return ecsString("process.pe.description", value)
}

// FileVersion create the ECS compliant 'process.pe.file_version' field.
// Internal version of the file, provided at compile-time.
func (nsProcessPe) FileVersion(value string) zapcore.Field {
	return ecsString("process.pe.file_version", value)
}

// Product create the ECS compliant 'process.pe.product' field.
// Internal product name of the file, provided at compile-time.
func (nsProcessPe) Product(value string) zapcore.Field {
	return ecsString("process.pe.product", value)
}

// Company create the ECS compliant 'process.pe.company' field.
// Internal company name of the file, provided at compile-time.
func (nsProcessPe) Company(value string) zapcore.Field {
	return ecsString("process.pe.company", value)
}

// ## process.thread fields

// Name create the ECS compliant 'process.thread.name' field.
// Thread name.
func (nsProcessThread) Name(value string) zapcore.Field {
	return ecsString("process.thread.name", value)
}

// ID create the ECS compliant 'process.thread.id' field.
// Thread ID.
func (nsProcessThread) ID(value int64) zapcore.Field {
	return ecsInt64("process.thread.id", value)
}

// ## registry fields

// Path create the ECS compliant 'registry.path' field.
// Full path, including hive, key and value
func (nsRegistry) Path(value string) zapcore.Field {
	return ecsString("registry.path", value)
}

// Value create the ECS compliant 'registry.value' field.
// Name of the value written.
func (nsRegistry) Value(value string) zapcore.Field {
	return ecsString("registry.value", value)
}

// Key create the ECS compliant 'registry.key' field.
// Hive-relative path of keys.
func (nsRegistry) Key(value string) zapcore.Field {
	return ecsString("registry.key", value)
}

// Hive create the ECS compliant 'registry.hive' field.
// Abbreviated name for the hive.
func (nsRegistry) Hive(value string) zapcore.Field {
	return ecsString("registry.hive", value)
}

// ## registry.data fields

// Strings create the ECS compliant 'registry.data.strings' field.
// Content when writing string types. Populated as an array when writing
// string data to the registry. For single string registry types (REG_SZ,
// REG_EXPAND_SZ), this should be an array with one string. For sequences
// of string with REG_MULTI_SZ, this array will be variable length. For
// numeric data, such as REG_DWORD and REG_QWORD, this should be populated
// with the decimal representation (e.g `"1"`).
func (nsRegistryData) Strings(value string) zapcore.Field {
	return ecsString("registry.data.strings", value)
}

// Type create the ECS compliant 'registry.data.type' field.
// Standard registry type for encoding contents
func (nsRegistryData) Type(value string) zapcore.Field {
	return ecsString("registry.data.type", value)
}

// Bytes create the ECS compliant 'registry.data.bytes' field.
// Original bytes written with base64 encoding. For Windows registry
// operations, such as SetValueEx and RegQueryValueEx, this corresponds to
// the data pointed by `lp_data`. This is optional but provides better
// recoverability and should be populated for REG_BINARY encoded values.
func (nsRegistryData) Bytes(value string) zapcore.Field {
	return ecsString("registry.data.bytes", value)
}

// ## related fields

// Hash create the ECS compliant 'related.hash' field.
// All the hashes seen on your event. Populating this field, then using it
// to search for hashes can help in situations where you're unsure what
// the hash algorithm is (and therefore which key name to search).
func (nsRelated) Hash(value string) zapcore.Field {
	return ecsString("related.hash", value)
}

// User create the ECS compliant 'related.user' field.
// All the user names seen on your event.
func (nsRelated) User(value string) zapcore.Field {
	return ecsString("related.user", value)
}

// IP create the ECS compliant 'related.ip' field.
// All of the IPs seen on your event.
func (nsRelated) IP(value string) zapcore.Field {
	return ecsString("related.ip", value)
}

// ## rule fields

// Author create the ECS compliant 'rule.author' field.
// Name, organization, or pseudonym of the author or authors who created
// the rule used to generate this event.
func (nsRule) Author(value string) zapcore.Field {
	return ecsString("rule.author", value)
}

// Reference create the ECS compliant 'rule.reference' field.
// Reference URL to additional information about the rule used to generate
// this event. The URL can point to the vendor's documentation about the
// rule. If that's not available, it can also be a link to a more general
// page describing this type of alert.
func (nsRule) Reference(value string) zapcore.Field {
	return ecsString("rule.reference", value)
}

// License create the ECS compliant 'rule.license' field.
// Name of the license under which the rule used to generate this event is
// made available.
func (nsRule) License(value string) zapcore.Field {
	return ecsString("rule.license", value)
}

// UUID create the ECS compliant 'rule.uuid' field.
// A rule ID that is unique within the scope of a set or group of agents,
// observers, or other entities using the rule for detection of this
// event.
func (nsRule) UUID(value string) zapcore.Field {
	return ecsString("rule.uuid", value)
}

// ID create the ECS compliant 'rule.id' field.
// A rule ID that is unique within the scope of an agent, observer, or
// other entity using the rule for detection of this event.
func (nsRule) ID(value string) zapcore.Field {
	return ecsString("rule.id", value)
}

// Version create the ECS compliant 'rule.version' field.
// The version / revision of the rule being used for analysis.
func (nsRule) Version(value string) zapcore.Field {
	return ecsString("rule.version", value)
}

// Name create the ECS compliant 'rule.name' field.
// The name of the rule or signature generating the event.
func (nsRule) Name(value string) zapcore.Field {
	return ecsString("rule.name", value)
}

// Ruleset create the ECS compliant 'rule.ruleset' field.
// Name of the ruleset, policy, group, or parent category in which the
// rule used to generate this event is a member.
func (nsRule) Ruleset(value string) zapcore.Field {
	return ecsString("rule.ruleset", value)
}

// Description create the ECS compliant 'rule.description' field.
// The description of the rule generating the event.
func (nsRule) Description(value string) zapcore.Field {
	return ecsString("rule.description", value)
}

// Category create the ECS compliant 'rule.category' field.
// A categorization value keyword used by the entity using the rule for
// detection of this event.
func (nsRule) Category(value string) zapcore.Field {
	return ecsString("rule.category", value)
}

// ## server fields

// Packets create the ECS compliant 'server.packets' field.
// Packets sent from the server to the client.
func (nsServer) Packets(value int64) zapcore.Field {
	return ecsInt64("server.packets", value)
}

// RegisteredDomain create the ECS compliant 'server.registered_domain' field.
// The highest registered server domain, stripped of the subdomain. For
// example, the registered domain for "foo.google.com" is "google.com".
// This value can be determined precisely with a list like the public
// suffix list (http://publicsuffix.org). Trying to approximate this by
// simply taking the last two labels will not work well for TLDs such as
// "co.uk".
func (nsServer) RegisteredDomain(value string) zapcore.Field {
	return ecsString("server.registered_domain", value)
}

// Domain create the ECS compliant 'server.domain' field.
// Server domain.
func (nsServer) Domain(value string) zapcore.Field {
	return ecsString("server.domain", value)
}

// Port create the ECS compliant 'server.port' field.
// Port of the server.
func (nsServer) Port(value int64) zapcore.Field {
	return ecsInt64("server.port", value)
}

// TopLevelDomain create the ECS compliant 'server.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (nsServer) TopLevelDomain(value string) zapcore.Field {
	return ecsString("server.top_level_domain", value)
}

// IP create the ECS compliant 'server.ip' field.
// IP address of the server. Can be one or multiple IPv4 or IPv6
// addresses.
func (nsServer) IP(value string) zapcore.Field {
	return ecsString("server.ip", value)
}

// Bytes create the ECS compliant 'server.bytes' field.
// Bytes sent from the server to the client.
func (nsServer) Bytes(value int64) zapcore.Field {
	return ecsInt64("server.bytes", value)
}

// Address create the ECS compliant 'server.address' field.
// Some event server addresses are defined ambiguously. The event will
// sometimes list an IP, a domain or a unix socket.  You should always
// store the raw address in the `.address` field. Then it should be
// duplicated to `.ip` or `.domain`, depending on which one it is.
func (nsServer) Address(value string) zapcore.Field {
	return ecsString("server.address", value)
}

// MAC create the ECS compliant 'server.mac' field.
// MAC address of the server.
func (nsServer) MAC(value string) zapcore.Field {
	return ecsString("server.mac", value)
}

// ## server.as fields

// Number create the ECS compliant 'server.as.number' field.
// Unique number allocated to the autonomous system. The autonomous system
// number (ASN) uniquely identifies each network on the Internet.
func (nsServerAs) Number(value int64) zapcore.Field {
	return ecsInt64("server.as.number", value)
}

// ## server.as.organization fields

// Name create the ECS compliant 'server.as.organization.name' field.
// Organization name.
func (nsServerAsOrganization) Name(value string) zapcore.Field {
	return ecsString("server.as.organization.name", value)
}

// ## server.geo fields

// ContinentName create the ECS compliant 'server.geo.continent_name' field.
// Name of the continent.
func (nsServerGeo) ContinentName(value string) zapcore.Field {
	return ecsString("server.geo.continent_name", value)
}

// RegionName create the ECS compliant 'server.geo.region_name' field.
// Region name.
func (nsServerGeo) RegionName(value string) zapcore.Field {
	return ecsString("server.geo.region_name", value)
}

// RegionIsoCode create the ECS compliant 'server.geo.region_iso_code' field.
// Region ISO code.
func (nsServerGeo) RegionIsoCode(value string) zapcore.Field {
	return ecsString("server.geo.region_iso_code", value)
}

// Location create the ECS compliant 'server.geo.location' field.
// Longitude and latitude.
func (nsServerGeo) Location(value string) zapcore.Field {
	return ecsString("server.geo.location", value)
}

// CountryIsoCode create the ECS compliant 'server.geo.country_iso_code' field.
// Country ISO code.
func (nsServerGeo) CountryIsoCode(value string) zapcore.Field {
	return ecsString("server.geo.country_iso_code", value)
}

// Name create the ECS compliant 'server.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (nsServerGeo) Name(value string) zapcore.Field {
	return ecsString("server.geo.name", value)
}

// CountryName create the ECS compliant 'server.geo.country_name' field.
// Country name.
func (nsServerGeo) CountryName(value string) zapcore.Field {
	return ecsString("server.geo.country_name", value)
}

// CityName create the ECS compliant 'server.geo.city_name' field.
// City name.
func (nsServerGeo) CityName(value string) zapcore.Field {
	return ecsString("server.geo.city_name", value)
}

// ## server.nat fields

// IP create the ECS compliant 'server.nat.ip' field.
// Translated ip of destination based NAT sessions (e.g. internet to
// private DMZ) Typically used with load balancers, firewalls, or routers.
func (nsServerNat) IP(value string) zapcore.Field {
	return ecsString("server.nat.ip", value)
}

// Port create the ECS compliant 'server.nat.port' field.
// Translated port of destination based NAT sessions (e.g. internet to
// private DMZ) Typically used with load balancers, firewalls, or routers.
func (nsServerNat) Port(value int64) zapcore.Field {
	return ecsInt64("server.nat.port", value)
}

// ## server.user fields

// FullName create the ECS compliant 'server.user.full_name' field.
// User's full name, if available.
func (nsServerUser) FullName(value string) zapcore.Field {
	return ecsString("server.user.full_name", value)
}

// Email create the ECS compliant 'server.user.email' field.
// User email address.
func (nsServerUser) Email(value string) zapcore.Field {
	return ecsString("server.user.email", value)
}

// Domain create the ECS compliant 'server.user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsServerUser) Domain(value string) zapcore.Field {
	return ecsString("server.user.domain", value)
}

// Hash create the ECS compliant 'server.user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (nsServerUser) Hash(value string) zapcore.Field {
	return ecsString("server.user.hash", value)
}

// Name create the ECS compliant 'server.user.name' field.
// Short name or login of the user.
func (nsServerUser) Name(value string) zapcore.Field {
	return ecsString("server.user.name", value)
}

// ID create the ECS compliant 'server.user.id' field.
// Unique identifiers of the user.
func (nsServerUser) ID(value string) zapcore.Field {
	return ecsString("server.user.id", value)
}

// ## server.user.group fields

// Name create the ECS compliant 'server.user.group.name' field.
// Name of the group.
func (nsServerUserGroup) Name(value string) zapcore.Field {
	return ecsString("server.user.group.name", value)
}

// Domain create the ECS compliant 'server.user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsServerUserGroup) Domain(value string) zapcore.Field {
	return ecsString("server.user.group.domain", value)
}

// ID create the ECS compliant 'server.user.group.id' field.
// Unique identifier for the group on the system/platform.
func (nsServerUserGroup) ID(value string) zapcore.Field {
	return ecsString("server.user.group.id", value)
}

// ## service fields

// Version create the ECS compliant 'service.version' field.
// Version of the service the data was collected from. This allows to look
// at a data set only for a specific version of a service.
func (nsService) Version(value string) zapcore.Field {
	return ecsString("service.version", value)
}

// State create the ECS compliant 'service.state' field.
// Current state of the service.
func (nsService) State(value string) zapcore.Field {
	return ecsString("service.state", value)
}

// EphemeralID create the ECS compliant 'service.ephemeral_id' field.
// Ephemeral identifier of this service (if one exists). This id normally
// changes across restarts, but `service.id` does not.
func (nsService) EphemeralID(value string) zapcore.Field {
	return ecsString("service.ephemeral_id", value)
}

// Name create the ECS compliant 'service.name' field.
// Name of the service data is collected from. The name of the service is
// normally user given. This allows for distributed services that run on
// multiple hosts to correlate the related instances based on the name. In
// the case of Elasticsearch the `service.name` could contain the cluster
// name. For Beats the `service.name` is by default a copy of the
// `service.type` field if no name is specified.
func (nsService) Name(value string) zapcore.Field {
	return ecsString("service.name", value)
}

// ID create the ECS compliant 'service.id' field.
// Unique identifier of the running service. If the service is comprised
// of many nodes, the `service.id` should be the same for all nodes. This
// id should uniquely identify the service. This makes it possible to
// correlate logs and metrics for one specific service, no matter which
// particular node emitted the event. Note that if you need to see the
// events from one specific host of the service, you should filter on that
// `host.name` or `host.id` instead.
func (nsService) ID(value string) zapcore.Field {
	return ecsString("service.id", value)
}

// Type create the ECS compliant 'service.type' field.
// The type of the service data is collected from. The type can be used to
// group and correlate logs and metrics from one service type. Example: If
// logs or metrics are collected from Elasticsearch, `service.type` would
// be `elasticsearch`.
func (nsService) Type(value string) zapcore.Field {
	return ecsString("service.type", value)
}

// ## service.node fields

// Name create the ECS compliant 'service.node.name' field.
// Name of a service node. This allows for two nodes of the same service
// running on the same host to be differentiated. Therefore,
// `service.node.name` should typically be unique across nodes of a given
// service. In the case of Elasticsearch, the `service.node.name` could
// contain the unique node name within the Elasticsearch cluster. In cases
// where the service doesn't have the concept of a node name, the host
// name or container name can be used to distinguish running instances
// that make up this service. If those do not provide uniqueness (e.g.
// multiple instances of the service running on the same host) - the node
// name can be manually set.
func (nsServiceNode) Name(value string) zapcore.Field {
	return ecsString("service.node.name", value)
}

// ## source fields

// Domain create the ECS compliant 'source.domain' field.
// Source domain.
func (nsSource) Domain(value string) zapcore.Field {
	return ecsString("source.domain", value)
}

// MAC create the ECS compliant 'source.mac' field.
// MAC address of the source.
func (nsSource) MAC(value string) zapcore.Field {
	return ecsString("source.mac", value)
}

// Bytes create the ECS compliant 'source.bytes' field.
// Bytes sent from the source to the destination.
func (nsSource) Bytes(value int64) zapcore.Field {
	return ecsInt64("source.bytes", value)
}

// IP create the ECS compliant 'source.ip' field.
// IP address of the source. Can be one or multiple IPv4 or IPv6
// addresses.
func (nsSource) IP(value string) zapcore.Field {
	return ecsString("source.ip", value)
}

// TopLevelDomain create the ECS compliant 'source.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (nsSource) TopLevelDomain(value string) zapcore.Field {
	return ecsString("source.top_level_domain", value)
}

// Port create the ECS compliant 'source.port' field.
// Port of the source.
func (nsSource) Port(value int64) zapcore.Field {
	return ecsInt64("source.port", value)
}

// Address create the ECS compliant 'source.address' field.
// Some event source addresses are defined ambiguously. The event will
// sometimes list an IP, a domain or a unix socket.  You should always
// store the raw address in the `.address` field. Then it should be
// duplicated to `.ip` or `.domain`, depending on which one it is.
func (nsSource) Address(value string) zapcore.Field {
	return ecsString("source.address", value)
}

// RegisteredDomain create the ECS compliant 'source.registered_domain' field.
// The highest registered source domain, stripped of the subdomain. For
// example, the registered domain for "foo.google.com" is "google.com".
// This value can be determined precisely with a list like the public
// suffix list (http://publicsuffix.org). Trying to approximate this by
// simply taking the last two labels will not work well for TLDs such as
// "co.uk".
func (nsSource) RegisteredDomain(value string) zapcore.Field {
	return ecsString("source.registered_domain", value)
}

// Packets create the ECS compliant 'source.packets' field.
// Packets sent from the source to the destination.
func (nsSource) Packets(value int64) zapcore.Field {
	return ecsInt64("source.packets", value)
}

// ## source.as fields

// Number create the ECS compliant 'source.as.number' field.
// Unique number allocated to the autonomous system. The autonomous system
// number (ASN) uniquely identifies each network on the Internet.
func (nsSourceAs) Number(value int64) zapcore.Field {
	return ecsInt64("source.as.number", value)
}

// ## source.as.organization fields

// Name create the ECS compliant 'source.as.organization.name' field.
// Organization name.
func (nsSourceAsOrganization) Name(value string) zapcore.Field {
	return ecsString("source.as.organization.name", value)
}

// ## source.geo fields

// CityName create the ECS compliant 'source.geo.city_name' field.
// City name.
func (nsSourceGeo) CityName(value string) zapcore.Field {
	return ecsString("source.geo.city_name", value)
}

// ContinentName create the ECS compliant 'source.geo.continent_name' field.
// Name of the continent.
func (nsSourceGeo) ContinentName(value string) zapcore.Field {
	return ecsString("source.geo.continent_name", value)
}

// RegionIsoCode create the ECS compliant 'source.geo.region_iso_code' field.
// Region ISO code.
func (nsSourceGeo) RegionIsoCode(value string) zapcore.Field {
	return ecsString("source.geo.region_iso_code", value)
}

// CountryIsoCode create the ECS compliant 'source.geo.country_iso_code' field.
// Country ISO code.
func (nsSourceGeo) CountryIsoCode(value string) zapcore.Field {
	return ecsString("source.geo.country_iso_code", value)
}

// RegionName create the ECS compliant 'source.geo.region_name' field.
// Region name.
func (nsSourceGeo) RegionName(value string) zapcore.Field {
	return ecsString("source.geo.region_name", value)
}

// Location create the ECS compliant 'source.geo.location' field.
// Longitude and latitude.
func (nsSourceGeo) Location(value string) zapcore.Field {
	return ecsString("source.geo.location", value)
}

// Name create the ECS compliant 'source.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (nsSourceGeo) Name(value string) zapcore.Field {
	return ecsString("source.geo.name", value)
}

// CountryName create the ECS compliant 'source.geo.country_name' field.
// Country name.
func (nsSourceGeo) CountryName(value string) zapcore.Field {
	return ecsString("source.geo.country_name", value)
}

// ## source.nat fields

// IP create the ECS compliant 'source.nat.ip' field.
// Translated ip of source based NAT sessions (e.g. internal client to
// internet) Typically connections traversing load balancers, firewalls,
// or routers.
func (nsSourceNat) IP(value string) zapcore.Field {
	return ecsString("source.nat.ip", value)
}

// Port create the ECS compliant 'source.nat.port' field.
// Translated port of source based NAT sessions. (e.g. internal client to
// internet) Typically used with load balancers, firewalls, or routers.
func (nsSourceNat) Port(value int64) zapcore.Field {
	return ecsInt64("source.nat.port", value)
}

// ## source.user fields

// Hash create the ECS compliant 'source.user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (nsSourceUser) Hash(value string) zapcore.Field {
	return ecsString("source.user.hash", value)
}

// Name create the ECS compliant 'source.user.name' field.
// Short name or login of the user.
func (nsSourceUser) Name(value string) zapcore.Field {
	return ecsString("source.user.name", value)
}

// Domain create the ECS compliant 'source.user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsSourceUser) Domain(value string) zapcore.Field {
	return ecsString("source.user.domain", value)
}

// Email create the ECS compliant 'source.user.email' field.
// User email address.
func (nsSourceUser) Email(value string) zapcore.Field {
	return ecsString("source.user.email", value)
}

// FullName create the ECS compliant 'source.user.full_name' field.
// User's full name, if available.
func (nsSourceUser) FullName(value string) zapcore.Field {
	return ecsString("source.user.full_name", value)
}

// ID create the ECS compliant 'source.user.id' field.
// Unique identifiers of the user.
func (nsSourceUser) ID(value string) zapcore.Field {
	return ecsString("source.user.id", value)
}

// ## source.user.group fields

// ID create the ECS compliant 'source.user.group.id' field.
// Unique identifier for the group on the system/platform.
func (nsSourceUserGroup) ID(value string) zapcore.Field {
	return ecsString("source.user.group.id", value)
}

// Name create the ECS compliant 'source.user.group.name' field.
// Name of the group.
func (nsSourceUserGroup) Name(value string) zapcore.Field {
	return ecsString("source.user.group.name", value)
}

// Domain create the ECS compliant 'source.user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsSourceUserGroup) Domain(value string) zapcore.Field {
	return ecsString("source.user.group.domain", value)
}

// ## threat fields

// Framework create the ECS compliant 'threat.framework' field.
// Name of the threat framework used to further categorize and classify
// the tactic and technique of the reported threat. Framework
// classification can be provided by detecting systems, evaluated at
// ingest time, or retrospectively tagged to events.
func (nsThreat) Framework(value string) zapcore.Field {
	return ecsString("threat.framework", value)
}

// ## threat.tactic fields

// Reference create the ECS compliant 'threat.tactic.reference' field.
// The reference url of tactic used by this threat. You can use the Mitre
// ATT&CK Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/tactics/TA0040/ )
func (nsThreatTactic) Reference(value string) zapcore.Field {
	return ecsString("threat.tactic.reference", value)
}

// ID create the ECS compliant 'threat.tactic.id' field.
// The id of tactic used by this threat. You can use the Mitre ATT&CK
// Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/tactics/TA0040/ )
func (nsThreatTactic) ID(value string) zapcore.Field {
	return ecsString("threat.tactic.id", value)
}

// Name create the ECS compliant 'threat.tactic.name' field.
// Name of the type of tactic used by this threat. You can use the Mitre
// ATT&CK Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/tactics/TA0040/ )
func (nsThreatTactic) Name(value string) zapcore.Field {
	return ecsString("threat.tactic.name", value)
}

// ## threat.technique fields

// ID create the ECS compliant 'threat.technique.id' field.
// The id of technique used by this tactic. You can use the Mitre ATT&CK
// Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/techniques/T1499/ )
func (nsThreatTechnique) ID(value string) zapcore.Field {
	return ecsString("threat.technique.id", value)
}

// Reference create the ECS compliant 'threat.technique.reference' field.
// The reference url of technique used by this tactic. You can use the
// Mitre ATT&CK Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/techniques/T1499/ )
func (nsThreatTechnique) Reference(value string) zapcore.Field {
	return ecsString("threat.technique.reference", value)
}

// Name create the ECS compliant 'threat.technique.name' field.
// The name of technique used by this tactic. You can use the Mitre ATT&CK
// Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/techniques/T1499/ )
func (nsThreatTechnique) Name(value string) zapcore.Field {
	return ecsString("threat.technique.name", value)
}

// ## tls fields

// Curve create the ECS compliant 'tls.curve' field.
// String indicating the curve used for the given cipher, when applicable.
func (nsTLS) Curve(value string) zapcore.Field {
	return ecsString("tls.curve", value)
}

// Resumed create the ECS compliant 'tls.resumed' field.
// Boolean flag indicating if this TLS connection was resumed from an
// existing TLS negotiation.
func (nsTLS) Resumed(value bool) zapcore.Field {
	return ecsBool("tls.resumed", value)
}

// NextProtocol create the ECS compliant 'tls.next_protocol' field.
// String indicating the protocol being tunneled. Per the values in the
// IANA registry
// (https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids),
// this string should be lower case.
func (nsTLS) NextProtocol(value string) zapcore.Field {
	return ecsString("tls.next_protocol", value)
}

// Version create the ECS compliant 'tls.version' field.
// Numeric part of the version parsed from the original string.
func (nsTLS) Version(value string) zapcore.Field {
	return ecsString("tls.version", value)
}

// Established create the ECS compliant 'tls.established' field.
// Boolean flag indicating if the TLS negotiation was successful and
// transitioned to an encrypted tunnel.
func (nsTLS) Established(value bool) zapcore.Field {
	return ecsBool("tls.established", value)
}

// Cipher create the ECS compliant 'tls.cipher' field.
// String indicating the cipher used during the current connection.
func (nsTLS) Cipher(value string) zapcore.Field {
	return ecsString("tls.cipher", value)
}

// VersionProtocol create the ECS compliant 'tls.version_protocol' field.
// Normalized lowercase protocol name parsed from original string.
func (nsTLS) VersionProtocol(value string) zapcore.Field {
	return ecsString("tls.version_protocol", value)
}

// ## tls.client fields

// Subject create the ECS compliant 'tls.client.subject' field.
// Distinguished name of subject of the x.509 certificate presented by the
// client.
func (nsTLSClient) Subject(value string) zapcore.Field {
	return ecsString("tls.client.subject", value)
}

// Certificate create the ECS compliant 'tls.client.certificate' field.
// PEM-encoded stand-alone certificate offered by the client. This is
// usually mutually-exclusive of `client.certificate_chain` since this
// value also exists in that list.
func (nsTLSClient) Certificate(value string) zapcore.Field {
	return ecsString("tls.client.certificate", value)
}

// CertificateChain create the ECS compliant 'tls.client.certificate_chain' field.
// Array of PEM-encoded certificates that make up the certificate chain
// offered by the client. This is usually mutually-exclusive of
// `client.certificate` since that value should be the first certificate
// in the chain.
func (nsTLSClient) CertificateChain(value string) zapcore.Field {
	return ecsString("tls.client.certificate_chain", value)
}

// SupportedCiphers create the ECS compliant 'tls.client.supported_ciphers' field.
// Array of ciphers offered by the client during the client hello.
func (nsTLSClient) SupportedCiphers(value string) zapcore.Field {
	return ecsString("tls.client.supported_ciphers", value)
}

// NotBefore create the ECS compliant 'tls.client.not_before' field.
// Date/Time indicating when client certificate is first considered valid.
func (nsTLSClient) NotBefore(value time.Time) zapcore.Field {
	return ecsTime("tls.client.not_before", value)
}

// NotAfter create the ECS compliant 'tls.client.not_after' field.
// Date/Time indicating when client certificate is no longer considered
// valid.
func (nsTLSClient) NotAfter(value time.Time) zapcore.Field {
	return ecsTime("tls.client.not_after", value)
}

// Ja3 create the ECS compliant 'tls.client.ja3' field.
// A hash that identifies clients based on how they perform an SSL/TLS
// handshake.
func (nsTLSClient) Ja3(value string) zapcore.Field {
	return ecsString("tls.client.ja3", value)
}

// ServerName create the ECS compliant 'tls.client.server_name' field.
// Also called an SNI, this tells the server which hostname to which the
// client is attempting to connect. When this value is available, it
// should get copied to `destination.domain`.
func (nsTLSClient) ServerName(value string) zapcore.Field {
	return ecsString("tls.client.server_name", value)
}

// Issuer create the ECS compliant 'tls.client.issuer' field.
// Distinguished name of subject of the issuer of the x.509 certificate
// presented by the client.
func (nsTLSClient) Issuer(value string) zapcore.Field {
	return ecsString("tls.client.issuer", value)
}

// ## tls.client.hash fields

// Sha1 create the ECS compliant 'tls.client.hash.sha1' field.
// Certificate fingerprint using the SHA1 digest of DER-encoded version of
// certificate offered by the client. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (nsTLSClientHash) Sha1(value string) zapcore.Field {
	return ecsString("tls.client.hash.sha1", value)
}

// Sha256 create the ECS compliant 'tls.client.hash.sha256' field.
// Certificate fingerprint using the SHA256 digest of DER-encoded version
// of certificate offered by the client. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (nsTLSClientHash) Sha256(value string) zapcore.Field {
	return ecsString("tls.client.hash.sha256", value)
}

// Md5 create the ECS compliant 'tls.client.hash.md5' field.
// Certificate fingerprint using the MD5 digest of DER-encoded version of
// certificate offered by the client. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (nsTLSClientHash) Md5(value string) zapcore.Field {
	return ecsString("tls.client.hash.md5", value)
}

// ## tls.server fields

// Ja3s create the ECS compliant 'tls.server.ja3s' field.
// A hash that identifies servers based on how they perform an SSL/TLS
// handshake.
func (nsTLSServer) Ja3s(value string) zapcore.Field {
	return ecsString("tls.server.ja3s", value)
}

// Certificate create the ECS compliant 'tls.server.certificate' field.
// PEM-encoded stand-alone certificate offered by the server. This is
// usually mutually-exclusive of `server.certificate_chain` since this
// value also exists in that list.
func (nsTLSServer) Certificate(value string) zapcore.Field {
	return ecsString("tls.server.certificate", value)
}

// Issuer create the ECS compliant 'tls.server.issuer' field.
// Subject of the issuer of the x.509 certificate presented by the server.
func (nsTLSServer) Issuer(value string) zapcore.Field {
	return ecsString("tls.server.issuer", value)
}

// CertificateChain create the ECS compliant 'tls.server.certificate_chain' field.
// Array of PEM-encoded certificates that make up the certificate chain
// offered by the server. This is usually mutually-exclusive of
// `server.certificate` since that value should be the first certificate
// in the chain.
func (nsTLSServer) CertificateChain(value string) zapcore.Field {
	return ecsString("tls.server.certificate_chain", value)
}

// NotBefore create the ECS compliant 'tls.server.not_before' field.
// Timestamp indicating when server certificate is first considered valid.
func (nsTLSServer) NotBefore(value time.Time) zapcore.Field {
	return ecsTime("tls.server.not_before", value)
}

// NotAfter create the ECS compliant 'tls.server.not_after' field.
// Timestamp indicating when server certificate is no longer considered
// valid.
func (nsTLSServer) NotAfter(value time.Time) zapcore.Field {
	return ecsTime("tls.server.not_after", value)
}

// Subject create the ECS compliant 'tls.server.subject' field.
// Subject of the x.509 certificate presented by the server.
func (nsTLSServer) Subject(value string) zapcore.Field {
	return ecsString("tls.server.subject", value)
}

// ## tls.server.hash fields

// Sha1 create the ECS compliant 'tls.server.hash.sha1' field.
// Certificate fingerprint using the SHA1 digest of DER-encoded version of
// certificate offered by the server. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (nsTLSServerHash) Sha1(value string) zapcore.Field {
	return ecsString("tls.server.hash.sha1", value)
}

// Md5 create the ECS compliant 'tls.server.hash.md5' field.
// Certificate fingerprint using the MD5 digest of DER-encoded version of
// certificate offered by the server. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (nsTLSServerHash) Md5(value string) zapcore.Field {
	return ecsString("tls.server.hash.md5", value)
}

// Sha256 create the ECS compliant 'tls.server.hash.sha256' field.
// Certificate fingerprint using the SHA256 digest of DER-encoded version
// of certificate offered by the server. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (nsTLSServerHash) Sha256(value string) zapcore.Field {
	return ecsString("tls.server.hash.sha256", value)
}

// ## trace fields

// ID create the ECS compliant 'trace.id' field.
// Unique identifier of the trace. A trace groups multiple events like
// transactions that belong together. For example, a user request handled
// by multiple inter-connected services.
func (nsTrace) ID(value string) zapcore.Field {
	return ecsString("trace.id", value)
}

// ## transaction fields

// ID create the ECS compliant 'transaction.id' field.
// Unique identifier of the transaction. A transaction is the highest
// level of work measured within a service, such as a request to a server.
func (nsTransaction) ID(value string) zapcore.Field {
	return ecsString("transaction.id", value)
}

// ## url fields

// TopLevelDomain create the ECS compliant 'url.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (nsURL) TopLevelDomain(value string) zapcore.Field {
	return ecsString("url.top_level_domain", value)
}

// Extension create the ECS compliant 'url.extension' field.
// The field contains the file extension from the original request url.
// The file extension is only set if it exists, as not every url has a
// file extension. The leading period must not be included. For example,
// the value must be "png", not ".png".
func (nsURL) Extension(value string) zapcore.Field {
	return ecsString("url.extension", value)
}

// Username create the ECS compliant 'url.username' field.
// Username of the request.
func (nsURL) Username(value string) zapcore.Field {
	return ecsString("url.username", value)
}

// Port create the ECS compliant 'url.port' field.
// Port of the request, such as 443.
func (nsURL) Port(value int64) zapcore.Field {
	return ecsInt64("url.port", value)
}

// Password create the ECS compliant 'url.password' field.
// Password of the request.
func (nsURL) Password(value string) zapcore.Field {
	return ecsString("url.password", value)
}

// Full create the ECS compliant 'url.full' field.
// If full URLs are important to your use case, they should be stored in
// `url.full`, whether this field is reconstructed or present in the event
// source.
func (nsURL) Full(value string) zapcore.Field {
	return ecsString("url.full", value)
}

// Domain create the ECS compliant 'url.domain' field.
// Domain of the url, such as "www.elastic.co". In some cases a URL may
// refer to an IP and/or port directly, without a domain name. In this
// case, the IP address would go to the `domain` field.
func (nsURL) Domain(value string) zapcore.Field {
	return ecsString("url.domain", value)
}

// Query create the ECS compliant 'url.query' field.
// The query field describes the query string of the request, such as
// "q=elasticsearch". The `?` is excluded from the query string. If a URL
// contains no `?`, there is no query field. If there is a `?` but no
// query, the query field exists with an empty string. The `exists` query
// can be used to differentiate between the two cases.
func (nsURL) Query(value string) zapcore.Field {
	return ecsString("url.query", value)
}

// Original create the ECS compliant 'url.original' field.
// Unmodified original url as seen in the event source. Note that in
// network monitoring, the observed URL may be a full URL, whereas in
// access logs, the URL is often just represented as a path. This field is
// meant to represent the URL as it was observed, complete or not.
func (nsURL) Original(value string) zapcore.Field {
	return ecsString("url.original", value)
}

// RegisteredDomain create the ECS compliant 'url.registered_domain' field.
// The highest registered url domain, stripped of the subdomain. For
// example, the registered domain for "foo.google.com" is "google.com".
// This value can be determined precisely with a list like the public
// suffix list (http://publicsuffix.org). Trying to approximate this by
// simply taking the last two labels will not work well for TLDs such as
// "co.uk".
func (nsURL) RegisteredDomain(value string) zapcore.Field {
	return ecsString("url.registered_domain", value)
}

// Fragment create the ECS compliant 'url.fragment' field.
// Portion of the url after the `#`, such as "top". The `#` is not part of
// the fragment.
func (nsURL) Fragment(value string) zapcore.Field {
	return ecsString("url.fragment", value)
}

// Scheme create the ECS compliant 'url.scheme' field.
// Scheme of the request, such as "https". Note: The `:` is not part of
// the scheme.
func (nsURL) Scheme(value string) zapcore.Field {
	return ecsString("url.scheme", value)
}

// Path create the ECS compliant 'url.path' field.
// Path of the request, such as "/search".
func (nsURL) Path(value string) zapcore.Field {
	return ecsString("url.path", value)
}

// ## user fields

// FullName create the ECS compliant 'user.full_name' field.
// User's full name, if available.
func (nsUser) FullName(value string) zapcore.Field {
	return ecsString("user.full_name", value)
}

// Name create the ECS compliant 'user.name' field.
// Short name or login of the user.
func (nsUser) Name(value string) zapcore.Field {
	return ecsString("user.name", value)
}

// ID create the ECS compliant 'user.id' field.
// Unique identifiers of the user.
func (nsUser) ID(value string) zapcore.Field {
	return ecsString("user.id", value)
}

// Email create the ECS compliant 'user.email' field.
// User email address.
func (nsUser) Email(value string) zapcore.Field {
	return ecsString("user.email", value)
}

// Domain create the ECS compliant 'user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsUser) Domain(value string) zapcore.Field {
	return ecsString("user.domain", value)
}

// Hash create the ECS compliant 'user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (nsUser) Hash(value string) zapcore.Field {
	return ecsString("user.hash", value)
}

// ## user.group fields

// Domain create the ECS compliant 'user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (nsUserGroup) Domain(value string) zapcore.Field {
	return ecsString("user.group.domain", value)
}

// Name create the ECS compliant 'user.group.name' field.
// Name of the group.
func (nsUserGroup) Name(value string) zapcore.Field {
	return ecsString("user.group.name", value)
}

// ID create the ECS compliant 'user.group.id' field.
// Unique identifier for the group on the system/platform.
func (nsUserGroup) ID(value string) zapcore.Field {
	return ecsString("user.group.id", value)
}

// ## user_agent fields

// Original create the ECS compliant 'user_agent.original' field.
// Unparsed user_agent string.
func (nsUserAgent) Original(value string) zapcore.Field {
	return ecsString("user_agent.original", value)
}

// Version create the ECS compliant 'user_agent.version' field.
// Version of the user agent.
func (nsUserAgent) Version(value string) zapcore.Field {
	return ecsString("user_agent.version", value)
}

// Name create the ECS compliant 'user_agent.name' field.
// Name of the user agent.
func (nsUserAgent) Name(value string) zapcore.Field {
	return ecsString("user_agent.name", value)
}

// ## user_agent.device fields

// Name create the ECS compliant 'user_agent.device.name' field.
// Name of the device.
func (nsUserAgentDevice) Name(value string) zapcore.Field {
	return ecsString("user_agent.device.name", value)
}

// ## user_agent.os fields

// Version create the ECS compliant 'user_agent.os.version' field.
// Operating system version as a raw string.
func (nsUserAgentOS) Version(value string) zapcore.Field {
	return ecsString("user_agent.os.version", value)
}

// Family create the ECS compliant 'user_agent.os.family' field.
// OS family (such as redhat, debian, freebsd, windows).
func (nsUserAgentOS) Family(value string) zapcore.Field {
	return ecsString("user_agent.os.family", value)
}

// Full create the ECS compliant 'user_agent.os.full' field.
// Operating system name, including the version or code name.
func (nsUserAgentOS) Full(value string) zapcore.Field {
	return ecsString("user_agent.os.full", value)
}

// Name create the ECS compliant 'user_agent.os.name' field.
// Operating system name, without the version.
func (nsUserAgentOS) Name(value string) zapcore.Field {
	return ecsString("user_agent.os.name", value)
}

// Kernel create the ECS compliant 'user_agent.os.kernel' field.
// Operating system kernel version as a raw string.
func (nsUserAgentOS) Kernel(value string) zapcore.Field {
	return ecsString("user_agent.os.kernel", value)
}

// Platform create the ECS compliant 'user_agent.os.platform' field.
// Operating system platform (such centos, ubuntu, windows).
func (nsUserAgentOS) Platform(value string) zapcore.Field {
	return ecsString("user_agent.os.platform", value)
}

// ## vlan fields

// Name create the ECS compliant 'vlan.name' field.
// Optional VLAN name as reported by the observer.
func (nsVlan) Name(value string) zapcore.Field {
	return ecsString("vlan.name", value)
}

// ID create the ECS compliant 'vlan.id' field.
// VLAN ID as reported by the observer.
func (nsVlan) ID(value string) zapcore.Field {
	return ecsString("vlan.id", value)
}

// ## vulnerability fields

// Category create the ECS compliant 'vulnerability.category' field.
// The type of system or architecture that the vulnerability affects.
// These may be platform-specific (for example, Debian or SUSE) or general
// (for example, Database or Firewall). For example
// (https://qualysguard.qualys.com/qwebhelp/fo_portal/knowledgebase/vulnerability_categories.htm[Qualys
// vulnerability categories]) This field must be an array.
func (nsVulnerability) Category(value string) zapcore.Field {
	return ecsString("vulnerability.category", value)
}

// Classification create the ECS compliant 'vulnerability.classification' field.
// The classification of the vulnerability scoring system. For example
// (https://www.first.org/cvss/)
func (nsVulnerability) Classification(value string) zapcore.Field {
	return ecsString("vulnerability.classification", value)
}

// Severity create the ECS compliant 'vulnerability.severity' field.
// The severity of the vulnerability can help with metrics and internal
// prioritization regarding remediation. For example
// (https://nvd.nist.gov/vuln-metrics/cvss)
func (nsVulnerability) Severity(value string) zapcore.Field {
	return ecsString("vulnerability.severity", value)
}

// ReportID create the ECS compliant 'vulnerability.report_id' field.
// The report or scan identification number.
func (nsVulnerability) ReportID(value string) zapcore.Field {
	return ecsString("vulnerability.report_id", value)
}

// ID create the ECS compliant 'vulnerability.id' field.
// The identification (ID) is the number portion of a vulnerability entry.
// It includes a unique identification number for the vulnerability. For
// example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common
// Vulnerabilities and Exposure CVE ID]
func (nsVulnerability) ID(value string) zapcore.Field {
	return ecsString("vulnerability.id", value)
}

// Description create the ECS compliant 'vulnerability.description' field.
// The description of the vulnerability that provides additional context
// of the vulnerability. For example
// (https://cve.mitre.org/about/faqs.html#cve_entry_descriptions_created[Common
// Vulnerabilities and Exposure CVE description])
func (nsVulnerability) Description(value string) zapcore.Field {
	return ecsString("vulnerability.description", value)
}

// Reference create the ECS compliant 'vulnerability.reference' field.
// A resource that provides additional information, context, and
// mitigations for the identified vulnerability.
func (nsVulnerability) Reference(value string) zapcore.Field {
	return ecsString("vulnerability.reference", value)
}

// Enumeration create the ECS compliant 'vulnerability.enumeration' field.
// The type of identifier used for this vulnerability. For example
// (https://cve.mitre.org/about/)
func (nsVulnerability) Enumeration(value string) zapcore.Field {
	return ecsString("vulnerability.enumeration", value)
}

// ## vulnerability.scanner fields

// Vendor create the ECS compliant 'vulnerability.scanner.vendor' field.
// The name of the vulnerability scanner vendor.
func (nsVulnerabilityScanner) Vendor(value string) zapcore.Field {
	return ecsString("vulnerability.scanner.vendor", value)
}

// ## vulnerability.score fields

// Base create the ECS compliant 'vulnerability.score.base' field.
// Scores can range from 0.0 to 10.0, with 10.0 being the most severe.
// Base scores cover an assessment for exploitability metrics (attack
// vector, complexity, privileges, and user interaction), impact metrics
// (confidentiality, integrity, and availability), and scope. For example
// (https://www.first.org/cvss/specification-document)
func (nsVulnerabilityScore) Base(value float64) zapcore.Field {
	return ecsFloat64("vulnerability.score.base", value)
}

// Environmental create the ECS compliant 'vulnerability.score.environmental' field.
// Scores can range from 0.0 to 10.0, with 10.0 being the most severe.
// Environmental scores cover an assessment for any modified Base metrics,
// confidentiality, integrity, and availability requirements. For example
// (https://www.first.org/cvss/specification-document)
func (nsVulnerabilityScore) Environmental(value float64) zapcore.Field {
	return ecsFloat64("vulnerability.score.environmental", value)
}

// Temporal create the ECS compliant 'vulnerability.score.temporal' field.
// Scores can range from 0.0 to 10.0, with 10.0 being the most severe.
// Temporal scores cover an assessment for code maturity, remediation
// level, and confidence. For example
// (https://www.first.org/cvss/specification-document)
func (nsVulnerabilityScore) Temporal(value float64) zapcore.Field {
	return ecsFloat64("vulnerability.score.temporal", value)
}

// Version create the ECS compliant 'vulnerability.score.version' field.
// The National Vulnerability Database (NVD) provides qualitative severity
// rankings of "Low", "Medium", and "High" for CVSS v2.0 base score ranges
// in addition to the severity ratings for CVSS v3.0 as they are defined
// in the CVSS v3.0 specification. CVSS is owned and managed by FIRST.Org,
// Inc. (FIRST), a US-based non-profit organization, whose mission is to
// help computer security incident response teams across the world. For
// example (https://nvd.nist.gov/vuln-metrics/cvss)
func (nsVulnerabilityScore) Version(value string) zapcore.Field {
	return ecsString("vulnerability.score.version", value)
}

type (
	nsAgent struct {
	}

	nsAs struct {
		Organization nsAsOrganization
	}

	nsAsOrganization struct {
	}

	nsClient struct {
		Geo nsClientGeo

		Nat nsClientNat

		User nsClientUser

		As nsClientAs
	}

	nsClientAs struct {
		Organization nsClientAsOrganization
	}

	nsClientAsOrganization struct {
	}

	nsClientGeo struct {
	}

	nsClientNat struct {
	}

	nsClientUser struct {
		Group nsClientUserGroup
	}

	nsClientUserGroup struct {
	}

	nsCloud struct {
		Instance nsCloudInstance

		Machine nsCloudMachine

		Account nsCloudAccount
	}

	nsCloudAccount struct {
	}

	nsCloudInstance struct {
	}

	nsCloudMachine struct {
	}

	nsCodeSignature struct {
	}

	nsContainer struct {
		Image nsContainerImage
	}

	nsContainerImage struct {
	}

	nsDestination struct {
		User nsDestinationUser

		Geo nsDestinationGeo

		As nsDestinationAs

		Nat nsDestinationNat
	}

	nsDestinationAs struct {
		Organization nsDestinationAsOrganization
	}

	nsDestinationAsOrganization struct {
	}

	nsDestinationGeo struct {
	}

	nsDestinationNat struct {
	}

	nsDestinationUser struct {
		Group nsDestinationUserGroup
	}

	nsDestinationUserGroup struct {
	}

	nsDll struct {
		Hash nsDllHash

		CodeSignature nsDllCodeSignature

		Pe nsDllPe
	}

	nsDllCodeSignature struct {
	}

	nsDllHash struct {
	}

	nsDllPe struct {
	}

	nsDNS struct {
		Answers nsDNSAnswers

		Question nsDNSQuestion
	}

	nsDNSAnswers struct {
	}

	nsDNSQuestion struct {
	}

	nsECS struct {
	}

	nsError struct {
	}

	nsEvent struct {
	}

	nsFile struct {
		Hash nsFileHash

		Pe nsFilePe

		CodeSignature nsFileCodeSignature
	}

	nsFileCodeSignature struct {
	}

	nsFileHash struct {
	}

	nsFilePe struct {
	}

	nsGeo struct {
	}

	nsGroup struct {
	}

	nsHash struct {
	}

	nsHost struct {
		OS nsHostOS

		Geo nsHostGeo

		User nsHostUser
	}

	nsHostGeo struct {
	}

	nsHostOS struct {
	}

	nsHostUser struct {
		Group nsHostUserGroup
	}

	nsHostUserGroup struct {
	}

	nsHTTP struct {
		Response nsHTTPResponse

		Request nsHTTPRequest
	}

	nsHTTPRequest struct {
		Body nsHTTPRequestBody
	}

	nsHTTPRequestBody struct {
	}

	nsHTTPResponse struct {
		Body nsHTTPResponseBody
	}

	nsHTTPResponseBody struct {
	}

	nsInterface struct {
	}

	nsLog struct {
		Origin nsLogOrigin

		Syslog nsLogSyslog
	}

	nsLogOrigin struct {
		File nsLogOriginFile
	}

	nsLogOriginFile struct {
	}

	nsLogSyslog struct {
		Severity nsLogSyslogSeverity

		Facility nsLogSyslogFacility
	}

	nsLogSyslogFacility struct {
	}

	nsLogSyslogSeverity struct {
	}

	nsNetwork struct {
		Vlan nsNetworkVlan

		Inner nsNetworkInner
	}

	nsNetworkInner struct {
		Vlan nsNetworkInnerVlan
	}

	nsNetworkInnerVlan struct {
	}

	nsNetworkVlan struct {
	}

	nsObserver struct {
		Geo nsObserverGeo

		Egress nsObserverEgress

		OS nsObserverOS

		Ingress nsObserverIngress
	}

	nsObserverEgress struct {
		Interface nsObserverEgressInterface

		Vlan nsObserverEgressVlan
	}

	nsObserverEgressInterface struct {
	}

	nsObserverEgressVlan struct {
	}

	nsObserverGeo struct {
	}

	nsObserverIngress struct {
		Interface nsObserverIngressInterface

		Vlan nsObserverIngressVlan
	}

	nsObserverIngressInterface struct {
	}

	nsObserverIngressVlan struct {
	}

	nsObserverOS struct {
	}

	nsOrganization struct {
	}

	nsOS struct {
	}

	nsPackage struct {
	}

	nsPe struct {
	}

	nsProcess struct {
		Parent nsProcessParent

		CodeSignature nsProcessCodeSignature

		Hash nsProcessHash

		Pe nsProcessPe

		Thread nsProcessThread
	}

	nsProcessCodeSignature struct {
	}

	nsProcessHash struct {
	}

	nsProcessParent struct {
		CodeSignature nsProcessParentCodeSignature

		Thread nsProcessParentThread

		Hash nsProcessParentHash
	}

	nsProcessParentCodeSignature struct {
	}

	nsProcessParentHash struct {
	}

	nsProcessParentThread struct {
	}

	nsProcessPe struct {
	}

	nsProcessThread struct {
	}

	nsRegistry struct {
		Data nsRegistryData
	}

	nsRegistryData struct {
	}

	nsRelated struct {
	}

	nsRule struct {
	}

	nsServer struct {
		Geo nsServerGeo

		As nsServerAs

		User nsServerUser

		Nat nsServerNat
	}

	nsServerAs struct {
		Organization nsServerAsOrganization
	}

	nsServerAsOrganization struct {
	}

	nsServerGeo struct {
	}

	nsServerNat struct {
	}

	nsServerUser struct {
		Group nsServerUserGroup
	}

	nsServerUserGroup struct {
	}

	nsService struct {
		Node nsServiceNode
	}

	nsServiceNode struct {
	}

	nsSource struct {
		Nat nsSourceNat

		Geo nsSourceGeo

		As nsSourceAs

		User nsSourceUser
	}

	nsSourceAs struct {
		Organization nsSourceAsOrganization
	}

	nsSourceAsOrganization struct {
	}

	nsSourceGeo struct {
	}

	nsSourceNat struct {
	}

	nsSourceUser struct {
		Group nsSourceUserGroup
	}

	nsSourceUserGroup struct {
	}

	nsThreat struct {
		Technique nsThreatTechnique

		Tactic nsThreatTactic
	}

	nsThreatTactic struct {
	}

	nsThreatTechnique struct {
	}

	nsTLS struct {
		Client nsTLSClient

		Server nsTLSServer
	}

	nsTLSClient struct {
		Hash nsTLSClientHash
	}

	nsTLSClientHash struct {
	}

	nsTLSServer struct {
		Hash nsTLSServerHash
	}

	nsTLSServerHash struct {
	}

	nsTrace struct {
	}

	nsTransaction struct {
	}

	nsURL struct {
	}

	nsUser struct {
		Group nsUserGroup
	}

	nsUserGroup struct {
	}

	nsUserAgent struct {
		OS nsUserAgentOS

		Device nsUserAgentDevice
	}

	nsUserAgentDevice struct {
	}

	nsUserAgentOS struct {
	}

	nsVlan struct {
	}

	nsVulnerability struct {
		Score nsVulnerabilityScore

		Scanner nsVulnerabilityScanner
	}

	nsVulnerabilityScanner struct {
	}

	nsVulnerabilityScore struct {
	}
)

func ecsTime(key string, val time.Time) zapcore.Field  { return zap.Time(key, val) }
func ecsString(key, val string) zapcore.Field          { return zap.String(key, val) }
func ecsBool(key string, val bool) zapcore.Field       { return zap.Bool(key, val) }
func ecsInt(key string, val int) zapcore.Field         { return zap.Int(key, val) }
func ecsInt64(key string, val int64) zapcore.Field     { return zap.Int64(key, val) }
func ecsFloat64(key string, val float64) zapcore.Field { return zap.Float64(key, val) }
