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

package ecs

// Do not manually change this file, as it is generated.
// If you want to update the file, run `mage update`

import (
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Field struct {

	// Agent provides fields in the ECS agent namespace.
	Agent Agent

	// As provides fields in the ECS as namespace.
	As As

	// Client provides fields in the ECS client namespace.
	Client Client

	// Cloud provides fields in the ECS cloud namespace.
	Cloud Cloud

	// CodeSignature provides fields in the ECS code_signature namespace.
	CodeSignature CodeSignature

	// Container provides fields in the ECS container namespace.
	Container Container

	// Destination provides fields in the ECS destination namespace.
	Destination Destination

	// Dll provides fields in the ECS dll namespace.
	Dll Dll

	// DNS provides fields in the ECS dns namespace.
	DNS DNS

	// ECS provides fields in the ECS ecs namespace.
	ECS ECS

	// Error provides fields in the ECS error namespace.
	Error Error

	// Event provides fields in the ECS event namespace.
	Event Event

	// File provides fields in the ECS file namespace.
	File File

	// Geo provides fields in the ECS geo namespace.
	Geo Geo

	// Group provides fields in the ECS group namespace.
	Group Group

	// Hash provides fields in the ECS hash namespace.
	Hash Hash

	// Host provides fields in the ECS host namespace.
	Host Host

	// HTTP provides fields in the ECS http namespace.
	HTTP HTTP

	// Interface provides fields in the ECS interface namespace.
	Interface Interface

	// Log provides fields in the ECS log namespace.
	Log Log

	// Network provides fields in the ECS network namespace.
	Network Network

	// Observer provides fields in the ECS observer namespace.
	Observer Observer

	// Organization provides fields in the ECS organization namespace.
	Organization Organization

	// OS provides fields in the ECS os namespace.
	OS OS

	// Package provides fields in the ECS package namespace.
	Package Package

	// Pe provides fields in the ECS pe namespace.
	Pe Pe

	// Process provides fields in the ECS process namespace.
	Process Process

	// Registry provides fields in the ECS registry namespace.
	Registry Registry

	// Related provides fields in the ECS related namespace.
	Related Related

	// Rule provides fields in the ECS rule namespace.
	Rule Rule

	// Server provides fields in the ECS server namespace.
	Server Server

	// Service provides fields in the ECS service namespace.
	Service Service

	// Source provides fields in the ECS source namespace.
	Source Source

	// Threat provides fields in the ECS threat namespace.
	Threat Threat

	// TLS provides fields in the ECS tls namespace.
	TLS TLS

	// Trace provides fields in the ECS trace namespace.
	Trace Trace

	// Transaction provides fields in the ECS transaction namespace.
	Transaction Transaction

	// URL provides fields in the ECS url namespace.
	URL URL

	// User provides fields in the ECS user namespace.
	User User

	// UserAgent provides fields in the ECS user_agent namespace.
	UserAgent UserAgent

	// Vlan provides fields in the ECS vlan namespace.
	Vlan Vlan

	// Vulnerability provides fields in the ECS vulnerability namespace.
	Vulnerability Vulnerability
}

type (
	Agent struct {
	}

	As struct {
		Organization AsOrganization
	}

	AsOrganization struct {
	}

	Client struct {
		Geo ClientGeo

		User ClientUser

		As ClientAs

		Nat ClientNat
	}

	ClientAs struct {
		Organization ClientAsOrganization
	}

	ClientAsOrganization struct {
	}

	ClientGeo struct {
	}

	ClientNat struct {
	}

	ClientUser struct {
		Group ClientUserGroup
	}

	ClientUserGroup struct {
	}

	Cloud struct {
		Account CloudAccount

		Instance CloudInstance

		Machine CloudMachine
	}

	CloudAccount struct {
	}

	CloudInstance struct {
	}

	CloudMachine struct {
	}

	CodeSignature struct {
	}

	Container struct {
		Image ContainerImage
	}

	ContainerImage struct {
	}

	Destination struct {
		Geo DestinationGeo

		Nat DestinationNat

		As DestinationAs

		User DestinationUser
	}

	DestinationAs struct {
		Organization DestinationAsOrganization
	}

	DestinationAsOrganization struct {
	}

	DestinationGeo struct {
	}

	DestinationNat struct {
	}

	DestinationUser struct {
		Group DestinationUserGroup
	}

	DestinationUserGroup struct {
	}

	Dll struct {
		Pe DllPe

		CodeSignature DllCodeSignature

		Hash DllHash
	}

	DllCodeSignature struct {
	}

	DllHash struct {
	}

	DllPe struct {
	}

	DNS struct {
		Answers DNSAnswers

		Question DNSQuestion
	}

	DNSAnswers struct {
	}

	DNSQuestion struct {
	}

	ECS struct {
	}

	Error struct {
	}

	Event struct {
	}

	File struct {
		CodeSignature FileCodeSignature

		Pe FilePe

		Hash FileHash
	}

	FileCodeSignature struct {
	}

	FileHash struct {
	}

	FilePe struct {
	}

	Geo struct {
	}

	Group struct {
	}

	Hash struct {
	}

	Host struct {
		Geo HostGeo

		OS HostOS

		User HostUser
	}

	HostGeo struct {
	}

	HostOS struct {
	}

	HostUser struct {
		Group HostUserGroup
	}

	HostUserGroup struct {
	}

	HTTP struct {
		Request HTTPRequest

		Response HTTPResponse
	}

	HTTPRequest struct {
		Body HTTPRequestBody
	}

	HTTPRequestBody struct {
	}

	HTTPResponse struct {
		Body HTTPResponseBody
	}

	HTTPResponseBody struct {
	}

	Interface struct {
	}

	Log struct {
		Origin LogOrigin

		Syslog LogSyslog
	}

	LogOrigin struct {
		File LogOriginFile
	}

	LogOriginFile struct {
	}

	LogSyslog struct {
		Facility LogSyslogFacility

		Severity LogSyslogSeverity
	}

	LogSyslogFacility struct {
	}

	LogSyslogSeverity struct {
	}

	Network struct {
		Vlan NetworkVlan

		Inner NetworkInner
	}

	NetworkInner struct {
		Vlan NetworkInnerVlan
	}

	NetworkInnerVlan struct {
	}

	NetworkVlan struct {
	}

	Observer struct {
		OS ObserverOS

		Egress ObserverEgress

		Geo ObserverGeo

		Ingress ObserverIngress
	}

	ObserverEgress struct {
		Interface ObserverEgressInterface

		Vlan ObserverEgressVlan
	}

	ObserverEgressInterface struct {
	}

	ObserverEgressVlan struct {
	}

	ObserverGeo struct {
	}

	ObserverIngress struct {
		Interface ObserverIngressInterface

		Vlan ObserverIngressVlan
	}

	ObserverIngressInterface struct {
	}

	ObserverIngressVlan struct {
	}

	ObserverOS struct {
	}

	Organization struct {
	}

	OS struct {
	}

	Package struct {
	}

	Pe struct {
	}

	Process struct {
		Hash ProcessHash

		Parent ProcessParent

		Thread ProcessThread

		Pe ProcessPe

		CodeSignature ProcessCodeSignature
	}

	ProcessCodeSignature struct {
	}

	ProcessHash struct {
	}

	ProcessParent struct {
		Hash ProcessParentHash

		Thread ProcessParentThread

		CodeSignature ProcessParentCodeSignature
	}

	ProcessParentCodeSignature struct {
	}

	ProcessParentHash struct {
	}

	ProcessParentThread struct {
	}

	ProcessPe struct {
	}

	ProcessThread struct {
	}

	Registry struct {
		Data RegistryData
	}

	RegistryData struct {
	}

	Related struct {
	}

	Rule struct {
	}

	Server struct {
		User ServerUser

		Nat ServerNat

		Geo ServerGeo

		As ServerAs
	}

	ServerAs struct {
		Organization ServerAsOrganization
	}

	ServerAsOrganization struct {
	}

	ServerGeo struct {
	}

	ServerNat struct {
	}

	ServerUser struct {
		Group ServerUserGroup
	}

	ServerUserGroup struct {
	}

	Service struct {
		Node ServiceNode
	}

	ServiceNode struct {
	}

	Source struct {
		Geo SourceGeo

		User SourceUser

		As SourceAs

		Nat SourceNat
	}

	SourceAs struct {
		Organization SourceAsOrganization
	}

	SourceAsOrganization struct {
	}

	SourceGeo struct {
	}

	SourceNat struct {
	}

	SourceUser struct {
		Group SourceUserGroup
	}

	SourceUserGroup struct {
	}

	Threat struct {
		Tactic ThreatTactic

		Technique ThreatTechnique
	}

	ThreatTactic struct {
	}

	ThreatTechnique struct {
	}

	TLS struct {
		Server TLSServer

		Client TLSClient
	}

	TLSClient struct {
		Hash TLSClientHash
	}

	TLSClientHash struct {
	}

	TLSServer struct {
		Hash TLSServerHash
	}

	TLSServerHash struct {
	}

	Trace struct {
	}

	Transaction struct {
	}

	URL struct {
	}

	User struct {
		Group UserGroup
	}

	UserGroup struct {
	}

	UserAgent struct {
		OS UserAgentOS

		Device UserAgentDevice
	}

	UserAgentDevice struct {
	}

	UserAgentOS struct {
	}

	Vlan struct {
	}

	Vulnerability struct {
		Score VulnerabilityScore

		Scanner VulnerabilityScanner
	}

	VulnerabilityScanner struct {
	}

	VulnerabilityScore struct {
	}
)

// Timestamp create the ECS compliant '@timestamp' field.
// Date/time when the event originated. This is the date/time extracted
// from the event, typically representing when the event was generated by
// the source. If the event source has no original timestamp, this value
// is typically populated by the first time the event was received by the
// pipeline. Required field for all events.
func Timestamp(value time.Time) zapcore.Field {
	return Time("@timestamp", value)
}

// Labels create the ECS compliant 'labels' field.
// Custom key/value pairs. Can be used to add meta information to events.
// Should not contain nested objects. All values are stored as keyword.
// Example: `docker` and `k8s` labels.
func Labels(value map[string]string) zapcore.Field {
	return MapStr("labels", value)
}

// Message create the ECS compliant 'message' field.
// For log events the message field contains the log message, optimized
// for viewing in a log viewer. For structured logs without an original
// message field, other fields can be concatenated to form a
// human-readable summary of the event. If multiple messages exist, they
// can be combined into one message.
func Message(value string) zapcore.Field {
	return String("message", value)
}

// Tags create the ECS compliant 'tags' field.
// List of keywords used to tag each event.
func Tags(value string) zapcore.Field {
	return String("tags", value)
}

// ## agent fields

// Type create the ECS compliant 'agent.type' field.
// Type of the agent. The agent type stays always the same and should be
// given by the agent used. In case of Filebeat the agent would always be
// Filebeat also if two Filebeat instances are run on the same machine.
func (Agent) Type(value string) zapcore.Field {
	return String("agent.type", value)
}

// Name create the ECS compliant 'agent.name' field.
// Custom name of the agent. This is a name that can be given to an agent.
// This can be helpful if for example two Filebeat instances are running
// on the same host but a human readable separation is needed on which
// Filebeat instance data is coming from. If no name is given, the name is
// often left empty.
func (Agent) Name(value string) zapcore.Field {
	return String("agent.name", value)
}

// EphemeralID create the ECS compliant 'agent.ephemeral_id' field.
// Ephemeral identifier of this agent (if one exists). This id normally
// changes across restarts, but `agent.id` does not.
func (Agent) EphemeralID(value string) zapcore.Field {
	return String("agent.ephemeral_id", value)
}

// Version create the ECS compliant 'agent.version' field.
// Version of the agent.
func (Agent) Version(value string) zapcore.Field {
	return String("agent.version", value)
}

// ID create the ECS compliant 'agent.id' field.
// Unique identifier of this agent (if one exists). Example: For Beats
// this would be beat.id.
func (Agent) ID(value string) zapcore.Field {
	return String("agent.id", value)
}

// ## as fields

// Number create the ECS compliant 'as.number' field.
// Unique number allocated to the autonomous system. The autonomous system
// number (ASN) uniquely identifies each network on the Internet.
func (As) Number(value int64) zapcore.Field {
	return Int64("as.number", value)
}

// ## as.organization fields

// Name create the ECS compliant 'as.organization.name' field.
// Organization name.
func (AsOrganization) Name(value string) zapcore.Field {
	return String("as.organization.name", value)
}

// ## client fields

// Packets create the ECS compliant 'client.packets' field.
// Packets sent from the client to the server.
func (Client) Packets(value int64) zapcore.Field {
	return Int64("client.packets", value)
}

// IP create the ECS compliant 'client.ip' field.
// IP address of the client. Can be one or multiple IPv4 or IPv6
// addresses.
func (Client) IP(value string) zapcore.Field {
	return String("client.ip", value)
}

// MAC create the ECS compliant 'client.mac' field.
// MAC address of the client.
func (Client) MAC(value string) zapcore.Field {
	return String("client.mac", value)
}

// Domain create the ECS compliant 'client.domain' field.
// Client domain.
func (Client) Domain(value string) zapcore.Field {
	return String("client.domain", value)
}

// Port create the ECS compliant 'client.port' field.
// Port of the client.
func (Client) Port(value int64) zapcore.Field {
	return Int64("client.port", value)
}

// Bytes create the ECS compliant 'client.bytes' field.
// Bytes sent from the client to the server.
func (Client) Bytes(value int64) zapcore.Field {
	return Int64("client.bytes", value)
}

// TopLevelDomain create the ECS compliant 'client.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (Client) TopLevelDomain(value string) zapcore.Field {
	return String("client.top_level_domain", value)
}

// RegisteredDomain create the ECS compliant 'client.registered_domain' field.
// The highest registered client domain, stripped of the subdomain. For
// example, the registered domain for "foo.google.com" is "google.com".
// This value can be determined precisely with a list like the public
// suffix list (http://publicsuffix.org). Trying to approximate this by
// simply taking the last two labels will not work well for TLDs such as
// "co.uk".
func (Client) RegisteredDomain(value string) zapcore.Field {
	return String("client.registered_domain", value)
}

// Address create the ECS compliant 'client.address' field.
// Some event client addresses are defined ambiguously. The event will
// sometimes list an IP, a domain or a unix socket.  You should always
// store the raw address in the `.address` field. Then it should be
// duplicated to `.ip` or `.domain`, depending on which one it is.
func (Client) Address(value string) zapcore.Field {
	return String("client.address", value)
}

// ## client.as fields

// Number create the ECS compliant 'client.as.number' field.
// Unique number allocated to the autonomous system. The autonomous system
// number (ASN) uniquely identifies each network on the Internet.
func (ClientAs) Number(value int64) zapcore.Field {
	return Int64("client.as.number", value)
}

// ## client.as.organization fields

// Name create the ECS compliant 'client.as.organization.name' field.
// Organization name.
func (ClientAsOrganization) Name(value string) zapcore.Field {
	return String("client.as.organization.name", value)
}

// ## client.geo fields

// Name create the ECS compliant 'client.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (ClientGeo) Name(value string) zapcore.Field {
	return String("client.geo.name", value)
}

// CityName create the ECS compliant 'client.geo.city_name' field.
// City name.
func (ClientGeo) CityName(value string) zapcore.Field {
	return String("client.geo.city_name", value)
}

// RegionName create the ECS compliant 'client.geo.region_name' field.
// Region name.
func (ClientGeo) RegionName(value string) zapcore.Field {
	return String("client.geo.region_name", value)
}

// CountryName create the ECS compliant 'client.geo.country_name' field.
// Country name.
func (ClientGeo) CountryName(value string) zapcore.Field {
	return String("client.geo.country_name", value)
}

// Location create the ECS compliant 'client.geo.location' field.
// Longitude and latitude.
func (ClientGeo) Location(value string) zapcore.Field {
	return String("client.geo.location", value)
}

// RegionIsoCode create the ECS compliant 'client.geo.region_iso_code' field.
// Region ISO code.
func (ClientGeo) RegionIsoCode(value string) zapcore.Field {
	return String("client.geo.region_iso_code", value)
}

// CountryIsoCode create the ECS compliant 'client.geo.country_iso_code' field.
// Country ISO code.
func (ClientGeo) CountryIsoCode(value string) zapcore.Field {
	return String("client.geo.country_iso_code", value)
}

// ContinentName create the ECS compliant 'client.geo.continent_name' field.
// Name of the continent.
func (ClientGeo) ContinentName(value string) zapcore.Field {
	return String("client.geo.continent_name", value)
}

// ## client.nat fields

// Port create the ECS compliant 'client.nat.port' field.
// Translated port of source based NAT sessions (e.g. internal client to
// internet). Typically connections traversing load balancers, firewalls,
// or routers.
func (ClientNat) Port(value int64) zapcore.Field {
	return Int64("client.nat.port", value)
}

// IP create the ECS compliant 'client.nat.ip' field.
// Translated IP of source based NAT sessions (e.g. internal client to
// internet). Typically connections traversing load balancers, firewalls,
// or routers.
func (ClientNat) IP(value string) zapcore.Field {
	return String("client.nat.ip", value)
}

// ## client.user fields

// Email create the ECS compliant 'client.user.email' field.
// User email address.
func (ClientUser) Email(value string) zapcore.Field {
	return String("client.user.email", value)
}

// FullName create the ECS compliant 'client.user.full_name' field.
// User's full name, if available.
func (ClientUser) FullName(value string) zapcore.Field {
	return String("client.user.full_name", value)
}

// Hash create the ECS compliant 'client.user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (ClientUser) Hash(value string) zapcore.Field {
	return String("client.user.hash", value)
}

// Domain create the ECS compliant 'client.user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (ClientUser) Domain(value string) zapcore.Field {
	return String("client.user.domain", value)
}

// ID create the ECS compliant 'client.user.id' field.
// Unique identifiers of the user.
func (ClientUser) ID(value string) zapcore.Field {
	return String("client.user.id", value)
}

// Name create the ECS compliant 'client.user.name' field.
// Short name or login of the user.
func (ClientUser) Name(value string) zapcore.Field {
	return String("client.user.name", value)
}

// ## client.user.group fields

// ID create the ECS compliant 'client.user.group.id' field.
// Unique identifier for the group on the system/platform.
func (ClientUserGroup) ID(value string) zapcore.Field {
	return String("client.user.group.id", value)
}

// Domain create the ECS compliant 'client.user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (ClientUserGroup) Domain(value string) zapcore.Field {
	return String("client.user.group.domain", value)
}

// Name create the ECS compliant 'client.user.group.name' field.
// Name of the group.
func (ClientUserGroup) Name(value string) zapcore.Field {
	return String("client.user.group.name", value)
}

// ## cloud fields

// Region create the ECS compliant 'cloud.region' field.
// Region in which this host is running.
func (Cloud) Region(value string) zapcore.Field {
	return String("cloud.region", value)
}

// Provider create the ECS compliant 'cloud.provider' field.
// Name of the cloud provider. Example values are aws, azure, gcp, or
// digitalocean.
func (Cloud) Provider(value string) zapcore.Field {
	return String("cloud.provider", value)
}

// AvailabilityZone create the ECS compliant 'cloud.availability_zone' field.
// Availability zone in which this host is running.
func (Cloud) AvailabilityZone(value string) zapcore.Field {
	return String("cloud.availability_zone", value)
}

// ## cloud.account fields

// ID create the ECS compliant 'cloud.account.id' field.
// The cloud account or organization id used to identify different
// entities in a multi-tenant environment. Examples: AWS account id,
// Google Cloud ORG Id, or other unique identifier.
func (CloudAccount) ID(value string) zapcore.Field {
	return String("cloud.account.id", value)
}

// ## cloud.instance fields

// ID create the ECS compliant 'cloud.instance.id' field.
// Instance ID of the host machine.
func (CloudInstance) ID(value string) zapcore.Field {
	return String("cloud.instance.id", value)
}

// Name create the ECS compliant 'cloud.instance.name' field.
// Instance name of the host machine.
func (CloudInstance) Name(value string) zapcore.Field {
	return String("cloud.instance.name", value)
}

// ## cloud.machine fields

// Type create the ECS compliant 'cloud.machine.type' field.
// Machine type of the host machine.
func (CloudMachine) Type(value string) zapcore.Field {
	return String("cloud.machine.type", value)
}

// ## code_signature fields

// Exists create the ECS compliant 'code_signature.exists' field.
// Boolean to capture if a signature is present.
func (CodeSignature) Exists(value bool) zapcore.Field {
	return Bool("code_signature.exists", value)
}

// Valid create the ECS compliant 'code_signature.valid' field.
// Boolean to capture if the digital signature is verified against the
// binary content. Leave unpopulated if a certificate was unchecked.
func (CodeSignature) Valid(value bool) zapcore.Field {
	return Bool("code_signature.valid", value)
}

// Trusted create the ECS compliant 'code_signature.trusted' field.
// Stores the trust status of the certificate chain. Validating the trust
// of the certificate chain may be complicated, and this field should only
// be populated by tools that actively check the status.
func (CodeSignature) Trusted(value bool) zapcore.Field {
	return Bool("code_signature.trusted", value)
}

// SubjectName create the ECS compliant 'code_signature.subject_name' field.
// Subject name of the code signer
func (CodeSignature) SubjectName(value string) zapcore.Field {
	return String("code_signature.subject_name", value)
}

// Status create the ECS compliant 'code_signature.status' field.
// Additional information about the certificate status. This is useful for
// logging cryptographic errors with the certificate validity or trust
// status. Leave unpopulated if the validity or trust of the certificate
// was unchecked.
func (CodeSignature) Status(value string) zapcore.Field {
	return String("code_signature.status", value)
}

// ## container fields

// Name create the ECS compliant 'container.name' field.
// Container name.
func (Container) Name(value string) zapcore.Field {
	return String("container.name", value)
}

// ID create the ECS compliant 'container.id' field.
// Unique container id.
func (Container) ID(value string) zapcore.Field {
	return String("container.id", value)
}

// Runtime create the ECS compliant 'container.runtime' field.
// Runtime managing this container.
func (Container) Runtime(value string) zapcore.Field {
	return String("container.runtime", value)
}

// ## container.image fields

// Name create the ECS compliant 'container.image.name' field.
// Name of the image the container was built on.
func (ContainerImage) Name(value string) zapcore.Field {
	return String("container.image.name", value)
}

// Tag create the ECS compliant 'container.image.tag' field.
// Container image tags.
func (ContainerImage) Tag(value string) zapcore.Field {
	return String("container.image.tag", value)
}

// ## destination fields

// Address create the ECS compliant 'destination.address' field.
// Some event destination addresses are defined ambiguously. The event
// will sometimes list an IP, a domain or a unix socket.  You should
// always store the raw address in the `.address` field. Then it should be
// duplicated to `.ip` or `.domain`, depending on which one it is.
func (Destination) Address(value string) zapcore.Field {
	return String("destination.address", value)
}

// Bytes create the ECS compliant 'destination.bytes' field.
// Bytes sent from the destination to the source.
func (Destination) Bytes(value int64) zapcore.Field {
	return Int64("destination.bytes", value)
}

// Packets create the ECS compliant 'destination.packets' field.
// Packets sent from the destination to the source.
func (Destination) Packets(value int64) zapcore.Field {
	return Int64("destination.packets", value)
}

// RegisteredDomain create the ECS compliant 'destination.registered_domain' field.
// The highest registered destination domain, stripped of the subdomain.
// For example, the registered domain for "foo.google.com" is
// "google.com". This value can be determined precisely with a list like
// the public suffix list (http://publicsuffix.org). Trying to approximate
// this by simply taking the last two labels will not work well for TLDs
// such as "co.uk".
func (Destination) RegisteredDomain(value string) zapcore.Field {
	return String("destination.registered_domain", value)
}

// IP create the ECS compliant 'destination.ip' field.
// IP address of the destination. Can be one or multiple IPv4 or IPv6
// addresses.
func (Destination) IP(value string) zapcore.Field {
	return String("destination.ip", value)
}

// Domain create the ECS compliant 'destination.domain' field.
// Destination domain.
func (Destination) Domain(value string) zapcore.Field {
	return String("destination.domain", value)
}

// MAC create the ECS compliant 'destination.mac' field.
// MAC address of the destination.
func (Destination) MAC(value string) zapcore.Field {
	return String("destination.mac", value)
}

// TopLevelDomain create the ECS compliant 'destination.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (Destination) TopLevelDomain(value string) zapcore.Field {
	return String("destination.top_level_domain", value)
}

// Port create the ECS compliant 'destination.port' field.
// Port of the destination.
func (Destination) Port(value int64) zapcore.Field {
	return Int64("destination.port", value)
}

// ## destination.as fields

// Number create the ECS compliant 'destination.as.number' field.
// Unique number allocated to the autonomous system. The autonomous system
// number (ASN) uniquely identifies each network on the Internet.
func (DestinationAs) Number(value int64) zapcore.Field {
	return Int64("destination.as.number", value)
}

// ## destination.as.organization fields

// Name create the ECS compliant 'destination.as.organization.name' field.
// Organization name.
func (DestinationAsOrganization) Name(value string) zapcore.Field {
	return String("destination.as.organization.name", value)
}

// ## destination.geo fields

// ContinentName create the ECS compliant 'destination.geo.continent_name' field.
// Name of the continent.
func (DestinationGeo) ContinentName(value string) zapcore.Field {
	return String("destination.geo.continent_name", value)
}

// RegionIsoCode create the ECS compliant 'destination.geo.region_iso_code' field.
// Region ISO code.
func (DestinationGeo) RegionIsoCode(value string) zapcore.Field {
	return String("destination.geo.region_iso_code", value)
}

// CountryIsoCode create the ECS compliant 'destination.geo.country_iso_code' field.
// Country ISO code.
func (DestinationGeo) CountryIsoCode(value string) zapcore.Field {
	return String("destination.geo.country_iso_code", value)
}

// CityName create the ECS compliant 'destination.geo.city_name' field.
// City name.
func (DestinationGeo) CityName(value string) zapcore.Field {
	return String("destination.geo.city_name", value)
}

// RegionName create the ECS compliant 'destination.geo.region_name' field.
// Region name.
func (DestinationGeo) RegionName(value string) zapcore.Field {
	return String("destination.geo.region_name", value)
}

// Location create the ECS compliant 'destination.geo.location' field.
// Longitude and latitude.
func (DestinationGeo) Location(value string) zapcore.Field {
	return String("destination.geo.location", value)
}

// Name create the ECS compliant 'destination.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (DestinationGeo) Name(value string) zapcore.Field {
	return String("destination.geo.name", value)
}

// CountryName create the ECS compliant 'destination.geo.country_name' field.
// Country name.
func (DestinationGeo) CountryName(value string) zapcore.Field {
	return String("destination.geo.country_name", value)
}

// ## destination.nat fields

// IP create the ECS compliant 'destination.nat.ip' field.
// Translated ip of destination based NAT sessions (e.g. internet to
// private DMZ) Typically used with load balancers, firewalls, or routers.
func (DestinationNat) IP(value string) zapcore.Field {
	return String("destination.nat.ip", value)
}

// Port create the ECS compliant 'destination.nat.port' field.
// Port the source session is translated to by NAT Device. Typically used
// with load balancers, firewalls, or routers.
func (DestinationNat) Port(value int64) zapcore.Field {
	return Int64("destination.nat.port", value)
}

// ## destination.user fields

// ID create the ECS compliant 'destination.user.id' field.
// Unique identifiers of the user.
func (DestinationUser) ID(value string) zapcore.Field {
	return String("destination.user.id", value)
}

// Domain create the ECS compliant 'destination.user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (DestinationUser) Domain(value string) zapcore.Field {
	return String("destination.user.domain", value)
}

// Hash create the ECS compliant 'destination.user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (DestinationUser) Hash(value string) zapcore.Field {
	return String("destination.user.hash", value)
}

// Name create the ECS compliant 'destination.user.name' field.
// Short name or login of the user.
func (DestinationUser) Name(value string) zapcore.Field {
	return String("destination.user.name", value)
}

// FullName create the ECS compliant 'destination.user.full_name' field.
// User's full name, if available.
func (DestinationUser) FullName(value string) zapcore.Field {
	return String("destination.user.full_name", value)
}

// Email create the ECS compliant 'destination.user.email' field.
// User email address.
func (DestinationUser) Email(value string) zapcore.Field {
	return String("destination.user.email", value)
}

// ## destination.user.group fields

// ID create the ECS compliant 'destination.user.group.id' field.
// Unique identifier for the group on the system/platform.
func (DestinationUserGroup) ID(value string) zapcore.Field {
	return String("destination.user.group.id", value)
}

// Domain create the ECS compliant 'destination.user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (DestinationUserGroup) Domain(value string) zapcore.Field {
	return String("destination.user.group.domain", value)
}

// Name create the ECS compliant 'destination.user.group.name' field.
// Name of the group.
func (DestinationUserGroup) Name(value string) zapcore.Field {
	return String("destination.user.group.name", value)
}

// ## dll fields

// Path create the ECS compliant 'dll.path' field.
// Full file path of the library.
func (Dll) Path(value string) zapcore.Field {
	return String("dll.path", value)
}

// Name create the ECS compliant 'dll.name' field.
// Name of the library. This generally maps to the name of the file on
// disk.
func (Dll) Name(value string) zapcore.Field {
	return String("dll.name", value)
}

// ## dll.code_signature fields

// SubjectName create the ECS compliant 'dll.code_signature.subject_name' field.
// Subject name of the code signer
func (DllCodeSignature) SubjectName(value string) zapcore.Field {
	return String("dll.code_signature.subject_name", value)
}

// Valid create the ECS compliant 'dll.code_signature.valid' field.
// Boolean to capture if the digital signature is verified against the
// binary content. Leave unpopulated if a certificate was unchecked.
func (DllCodeSignature) Valid(value bool) zapcore.Field {
	return Bool("dll.code_signature.valid", value)
}

// Exists create the ECS compliant 'dll.code_signature.exists' field.
// Boolean to capture if a signature is present.
func (DllCodeSignature) Exists(value bool) zapcore.Field {
	return Bool("dll.code_signature.exists", value)
}

// Status create the ECS compliant 'dll.code_signature.status' field.
// Additional information about the certificate status. This is useful for
// logging cryptographic errors with the certificate validity or trust
// status. Leave unpopulated if the validity or trust of the certificate
// was unchecked.
func (DllCodeSignature) Status(value string) zapcore.Field {
	return String("dll.code_signature.status", value)
}

// Trusted create the ECS compliant 'dll.code_signature.trusted' field.
// Stores the trust status of the certificate chain. Validating the trust
// of the certificate chain may be complicated, and this field should only
// be populated by tools that actively check the status.
func (DllCodeSignature) Trusted(value bool) zapcore.Field {
	return Bool("dll.code_signature.trusted", value)
}

// ## dll.hash fields

// Sha1 create the ECS compliant 'dll.hash.sha1' field.
// SHA1 hash.
func (DllHash) Sha1(value string) zapcore.Field {
	return String("dll.hash.sha1", value)
}

// Sha256 create the ECS compliant 'dll.hash.sha256' field.
// SHA256 hash.
func (DllHash) Sha256(value string) zapcore.Field {
	return String("dll.hash.sha256", value)
}

// Sha512 create the ECS compliant 'dll.hash.sha512' field.
// SHA512 hash.
func (DllHash) Sha512(value string) zapcore.Field {
	return String("dll.hash.sha512", value)
}

// Md5 create the ECS compliant 'dll.hash.md5' field.
// MD5 hash.
func (DllHash) Md5(value string) zapcore.Field {
	return String("dll.hash.md5", value)
}

// ## dll.pe fields

// FileVersion create the ECS compliant 'dll.pe.file_version' field.
// Internal version of the file, provided at compile-time.
func (DllPe) FileVersion(value string) zapcore.Field {
	return String("dll.pe.file_version", value)
}

// Product create the ECS compliant 'dll.pe.product' field.
// Internal product name of the file, provided at compile-time.
func (DllPe) Product(value string) zapcore.Field {
	return String("dll.pe.product", value)
}

// Company create the ECS compliant 'dll.pe.company' field.
// Internal company name of the file, provided at compile-time.
func (DllPe) Company(value string) zapcore.Field {
	return String("dll.pe.company", value)
}

// OriginalFileName create the ECS compliant 'dll.pe.original_file_name' field.
// Internal name of the file, provided at compile-time.
func (DllPe) OriginalFileName(value string) zapcore.Field {
	return String("dll.pe.original_file_name", value)
}

// Description create the ECS compliant 'dll.pe.description' field.
// Internal description of the file, provided at compile-time.
func (DllPe) Description(value string) zapcore.Field {
	return String("dll.pe.description", value)
}

// ## dns fields

// Type create the ECS compliant 'dns.type' field.
// The type of DNS event captured, query or answer. If your source of DNS
// events only gives you DNS queries, you should only create dns events of
// type `dns.type:query`. If your source of DNS events gives you answers
// as well, you should create one event per query (optionally as soon as
// the query is seen). And a second event containing all query details as
// well as an array of answers.
func (DNS) Type(value string) zapcore.Field {
	return String("dns.type", value)
}

// OpCode create the ECS compliant 'dns.op_code' field.
// The DNS operation code that specifies the kind of query in the message.
// This value is set by the originator of a query and copied into the
// response.
func (DNS) OpCode(value string) zapcore.Field {
	return String("dns.op_code", value)
}

// ResolvedIP create the ECS compliant 'dns.resolved_ip' field.
// Array containing all IPs seen in `answers.data`. The `answers` array
// can be difficult to use, because of the variety of data formats it can
// contain. Extracting all IP addresses seen in there to `dns.resolved_ip`
// makes it possible to index them as IP addresses, and makes them easier
// to visualize and query for.
func (DNS) ResolvedIP(value string) zapcore.Field {
	return String("dns.resolved_ip", value)
}

// ResponseCode create the ECS compliant 'dns.response_code' field.
// The DNS response code.
func (DNS) ResponseCode(value string) zapcore.Field {
	return String("dns.response_code", value)
}

// HeaderFlags create the ECS compliant 'dns.header_flags' field.
// Array of 2 letter DNS header flags. Expected values are: AA, TC, RD,
// RA, AD, CD, DO.
func (DNS) HeaderFlags(value string) zapcore.Field {
	return String("dns.header_flags", value)
}

// ID create the ECS compliant 'dns.id' field.
// The DNS packet identifier assigned by the program that generated the
// query. The identifier is copied to the response.
func (DNS) ID(value string) zapcore.Field {
	return String("dns.id", value)
}

// ## dns.answers fields

// TTL create the ECS compliant 'dns.answers.ttl' field.
// The time interval in seconds that this resource record may be cached
// before it should be discarded. Zero values mean that the data should
// not be cached.
func (DNSAnswers) TTL(value int64) zapcore.Field {
	return Int64("dns.answers.ttl", value)
}

// Data create the ECS compliant 'dns.answers.data' field.
// The data describing the resource. The meaning of this data depends on
// the type and class of the resource record.
func (DNSAnswers) Data(value string) zapcore.Field {
	return String("dns.answers.data", value)
}

// Name create the ECS compliant 'dns.answers.name' field.
// The domain name to which this resource record pertains. If a chain of
// CNAME is being resolved, each answer's `name` should be the one that
// corresponds with the answer's `data`. It should not simply be the
// original `question.name` repeated.
func (DNSAnswers) Name(value string) zapcore.Field {
	return String("dns.answers.name", value)
}

// Type create the ECS compliant 'dns.answers.type' field.
// The type of data contained in this resource record.
func (DNSAnswers) Type(value string) zapcore.Field {
	return String("dns.answers.type", value)
}

// Class create the ECS compliant 'dns.answers.class' field.
// The class of DNS data contained in this resource record.
func (DNSAnswers) Class(value string) zapcore.Field {
	return String("dns.answers.class", value)
}

// ## dns.question fields

// Class create the ECS compliant 'dns.question.class' field.
// The class of records being queried.
func (DNSQuestion) Class(value string) zapcore.Field {
	return String("dns.question.class", value)
}

// Type create the ECS compliant 'dns.question.type' field.
// The type of record being queried.
func (DNSQuestion) Type(value string) zapcore.Field {
	return String("dns.question.type", value)
}

// Subdomain create the ECS compliant 'dns.question.subdomain' field.
// The subdomain is all of the labels under the registered_domain. If the
// domain has multiple levels of subdomain, such as
// "sub2.sub1.example.com", the subdomain field should contain
// "sub2.sub1", with no trailing period.
func (DNSQuestion) Subdomain(value string) zapcore.Field {
	return String("dns.question.subdomain", value)
}

// Name create the ECS compliant 'dns.question.name' field.
// The name being queried. If the name field contains non-printable
// characters (below 32 or above 126), those characters should be
// represented as escaped base 10 integers (\DDD). Back slashes and quotes
// should be escaped. Tabs, carriage returns, and line feeds should be
// converted to \t, \r, and \n respectively.
func (DNSQuestion) Name(value string) zapcore.Field {
	return String("dns.question.name", value)
}

// RegisteredDomain create the ECS compliant 'dns.question.registered_domain' field.
// The highest registered domain, stripped of the subdomain. For example,
// the registered domain for "foo.google.com" is "google.com". This value
// can be determined precisely with a list like the public suffix list
// (http://publicsuffix.org). Trying to approximate this by simply taking
// the last two labels will not work well for TLDs such as "co.uk".
func (DNSQuestion) RegisteredDomain(value string) zapcore.Field {
	return String("dns.question.registered_domain", value)
}

// TopLevelDomain create the ECS compliant 'dns.question.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (DNSQuestion) TopLevelDomain(value string) zapcore.Field {
	return String("dns.question.top_level_domain", value)
}

// ## ecs fields

// Version create the ECS compliant 'ecs.version' field.
// ECS version this event conforms to. `ecs.version` is a required field
// and must exist in all events. When querying across multiple indices --
// which may conform to slightly different ECS versions -- this field lets
// integrations adjust to the schema version of the events.
func (ECS) Version(value string) zapcore.Field {
	return String("ecs.version", value)
}

// ## error fields

// Message create the ECS compliant 'error.message' field.
// Error message.
func (Error) Message(value string) zapcore.Field {
	return String("error.message", value)
}

// Type create the ECS compliant 'error.type' field.
// The type of the error, for example the class name of the exception.
func (Error) Type(value string) zapcore.Field {
	return String("error.type", value)
}

// StackTrace create the ECS compliant 'error.stack_trace' field.
// The stack trace of this error in plain text.
func (Error) StackTrace(value string) zapcore.Field {
	return String("error.stack_trace", value)
}

// Code create the ECS compliant 'error.code' field.
// Error code describing the error.
func (Error) Code(value string) zapcore.Field {
	return String("error.code", value)
}

// ID create the ECS compliant 'error.id' field.
// Unique identifier for the error.
func (Error) ID(value string) zapcore.Field {
	return String("error.id", value)
}

// ## event fields

// End create the ECS compliant 'event.end' field.
// event.end contains the date when the event ended or when the activity
// was last observed.
func (Event) End(value time.Time) zapcore.Field {
	return Time("event.end", value)
}

// Reference create the ECS compliant 'event.reference' field.
// Reference URL linking to additional information about this event. This
// URL links to a static definition of the this event. Alert events,
// indicated by `event.kind:alert`, are a common use case for this field.
func (Event) Reference(value string) zapcore.Field {
	return String("event.reference", value)
}

// Type create the ECS compliant 'event.type' field.
// This is one of four ECS Categorization Fields, and indicates the third
// level in the ECS category hierarchy. `event.type` represents a
// categorization "sub-bucket" that, when used along with the
// `event.category` field values, enables filtering events down to a level
// appropriate for single visualization. This field is an array. This will
// allow proper categorization of some events that fall in multiple event
// types.
func (Event) Type(value string) zapcore.Field {
	return String("event.type", value)
}

// Original create the ECS compliant 'event.original' field.
// Raw text message of entire event. Used to demonstrate log integrity.
// This field is not indexed and doc_values are disabled. It cannot be
// searched, but it can be retrieved from `_source`.
func (Event) Original(value string) zapcore.Field {
	return String("event.original", value)
}

// Sequence create the ECS compliant 'event.sequence' field.
// Sequence number of the event. The sequence number is a value published
// by some event sources, to make the exact ordering of events
// unambiguous, regardless of the timestamp precision.
func (Event) Sequence(value int64) zapcore.Field {
	return Int64("event.sequence", value)
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
func (Event) Severity(value int64) zapcore.Field {
	return Int64("event.severity", value)
}

// Duration create the ECS compliant 'event.duration' field.
// Duration of the event in nanoseconds. If event.start and event.end are
// known this value should be the difference between the end and start
// time.
func (Event) Duration(value int64) zapcore.Field {
	return Int64("event.duration", value)
}

// RiskScoreNorm create the ECS compliant 'event.risk_score_norm' field.
// Normalized risk score or priority of the event, on a scale of 0 to 100.
// This is mainly useful if you use more than one system that assigns risk
// scores, and you want to see a normalized value across all systems.
func (Event) RiskScoreNorm(value float64) zapcore.Field {
	return Float64("event.risk_score_norm", value)
}

// Action create the ECS compliant 'event.action' field.
// The action captured by the event. This describes the information in the
// event. It is more specific than `event.category`. Examples are
// `group-add`, `process-started`, `file-created`. The value is normally
// defined by the implementer.
func (Event) Action(value string) zapcore.Field {
	return String("event.action", value)
}

// Dataset create the ECS compliant 'event.dataset' field.
// Name of the dataset. If an event source publishes more than one type of
// log or events (e.g. access log, error log), the dataset is used to
// specify which one the event comes from. It's recommended but not
// required to start the dataset name with the module name, followed by a
// dot, then the dataset name.
func (Event) Dataset(value string) zapcore.Field {
	return String("event.dataset", value)
}

// Provider create the ECS compliant 'event.provider' field.
// Source of the event. Event transports such as Syslog or the Windows
// Event Log typically mention the source of an event. It can be the name
// of the software that generated the event (e.g. Sysmon, httpd), or of a
// subsystem of the operating system (kernel,
// Microsoft-Windows-Security-Auditing).
func (Event) Provider(value string) zapcore.Field {
	return String("event.provider", value)
}

// Code create the ECS compliant 'event.code' field.
// Identification code for this event, if one exists. Some event sources
// use event codes to identify messages unambiguously, regardless of
// message language or wording adjustments over time. An example of this
// is the Windows Event ID.
func (Event) Code(value string) zapcore.Field {
	return String("event.code", value)
}

// RiskScore create the ECS compliant 'event.risk_score' field.
// Risk score or priority of the event (e.g. security solutions). Use your
// system's original value here.
func (Event) RiskScore(value float64) zapcore.Field {
	return Float64("event.risk_score", value)
}

// Module create the ECS compliant 'event.module' field.
// Name of the module this data is coming from. If your monitoring agent
// supports the concept of modules or plugins to process events of a given
// source (e.g. Apache logs), `event.module` should contain the name of
// this module.
func (Event) Module(value string) zapcore.Field {
	return String("event.module", value)
}

// Ingested create the ECS compliant 'event.ingested' field.
// Timestamp when an event arrived in the central data store. This is
// different from `@timestamp`, which is when the event originally
// occurred.  It's also different from `event.created`, which is meant to
// capture the first time an agent saw the event. In normal conditions,
// assuming no tampering, the timestamps should chronologically look like
// this: `@timestamp` < `event.created` < `event.ingested`.
func (Event) Ingested(value time.Time) zapcore.Field {
	return Time("event.ingested", value)
}

// URL create the ECS compliant 'event.url' field.
// URL linking to an external system to continue investigation of this
// event. This URL links to another system where in-depth investigation of
// the specific occurence of this event can take place. Alert events,
// indicated by `event.kind:alert`, are a common use case for this field.
func (Event) URL(value string) zapcore.Field {
	return String("event.url", value)
}

// Start create the ECS compliant 'event.start' field.
// event.start contains the date when the event started or when the
// activity was first observed.
func (Event) Start(value time.Time) zapcore.Field {
	return Time("event.start", value)
}

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
func (Event) Kind(value string) zapcore.Field {
	return String("event.kind", value)
}

// Timezone create the ECS compliant 'event.timezone' field.
// This field should be populated when the event's timestamp does not
// include timezone information already (e.g. default Syslog timestamps).
// It's optional otherwise. Acceptable timezone formats are: a canonical
// ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm
// differential (e.g. "-05:00").
func (Event) Timezone(value string) zapcore.Field {
	return String("event.timezone", value)
}

// ID create the ECS compliant 'event.id' field.
// Unique ID to describe the event.
func (Event) ID(value string) zapcore.Field {
	return String("event.id", value)
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
func (Event) Outcome(value string) zapcore.Field {
	return String("event.outcome", value)
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
func (Event) Created(value time.Time) zapcore.Field {
	return Time("event.created", value)
}

// Category create the ECS compliant 'event.category' field.
// This is one of four ECS Categorization Fields, and indicates the second
// level in the ECS category hierarchy. `event.category` represents the
// "big buckets" of ECS categories. For example, filtering on
// `event.category:process` yields all events relating to process
// activity. This field is closely related to `event.type`, which is used
// as a subcategory. This field is an array. This will allow proper
// categorization of some events that fall in multiple categories.
func (Event) Category(value string) zapcore.Field {
	return String("event.category", value)
}

// Hash create the ECS compliant 'event.hash' field.
// Hash (perhaps logstash fingerprint) of raw field to be able to
// demonstrate log integrity.
func (Event) Hash(value string) zapcore.Field {
	return String("event.hash", value)
}

// ## file fields

// Device create the ECS compliant 'file.device' field.
// Device that is the source of the file.
func (File) Device(value string) zapcore.Field {
	return String("file.device", value)
}

// Ctime create the ECS compliant 'file.ctime' field.
// Last time the file attributes or metadata changed. Note that changes to
// the file content will update `mtime`. This implies `ctime` will be
// adjusted at the same time, since `mtime` is an attribute of the file.
func (File) Ctime(value time.Time) zapcore.Field {
	return Time("file.ctime", value)
}

// Group create the ECS compliant 'file.group' field.
// Primary group name of the file.
func (File) Group(value string) zapcore.Field {
	return String("file.group", value)
}

// Name create the ECS compliant 'file.name' field.
// Name of the file including the extension, without the directory.
func (File) Name(value string) zapcore.Field {
	return String("file.name", value)
}

// DriveLetter create the ECS compliant 'file.drive_letter' field.
// Drive letter where the file is located. This field is only relevant on
// Windows. The value should be uppercase, and not include the colon.
func (File) DriveLetter(value string) zapcore.Field {
	return String("file.drive_letter", value)
}

// TargetPath create the ECS compliant 'file.target_path' field.
// Target path for symlinks.
func (File) TargetPath(value string) zapcore.Field {
	return String("file.target_path", value)
}

// Mtime create the ECS compliant 'file.mtime' field.
// Last time the file content was modified.
func (File) Mtime(value time.Time) zapcore.Field {
	return Time("file.mtime", value)
}

// Created create the ECS compliant 'file.created' field.
// File creation time. Note that not all filesystems store the creation
// time.
func (File) Created(value time.Time) zapcore.Field {
	return Time("file.created", value)
}

// UID create the ECS compliant 'file.uid' field.
// The user ID (UID) or security identifier (SID) of the file owner.
func (File) UID(value string) zapcore.Field {
	return String("file.uid", value)
}

// MimeType create the ECS compliant 'file.mime_type' field.
// MIME type should identify the format of the file or stream of bytes
// using
// https://www.iana.org/assignments/media-types/media-types.xhtml[IANA
// official types], where possible. When more than one type is applicable,
// the most specific type should be used.
func (File) MimeType(value string) zapcore.Field {
	return String("file.mime_type", value)
}

// Size create the ECS compliant 'file.size' field.
// File size in bytes. Only relevant when `file.type` is "file".
func (File) Size(value int64) zapcore.Field {
	return Int64("file.size", value)
}

// Gid create the ECS compliant 'file.gid' field.
// Primary group ID (GID) of the file.
func (File) Gid(value string) zapcore.Field {
	return String("file.gid", value)
}

// Extension create the ECS compliant 'file.extension' field.
// File extension.
func (File) Extension(value string) zapcore.Field {
	return String("file.extension", value)
}

// Attributes create the ECS compliant 'file.attributes' field.
// Array of file attributes. Attributes names will vary by platform.
// Here's a non-exhaustive list of values that are expected in this field:
// archive, compressed, directory, encrypted, execute, hidden, read,
// readonly, system, write.
func (File) Attributes(value string) zapcore.Field {
	return String("file.attributes", value)
}

// Directory create the ECS compliant 'file.directory' field.
// Directory where the file is located. It should include the drive
// letter, when appropriate.
func (File) Directory(value string) zapcore.Field {
	return String("file.directory", value)
}

// Mode create the ECS compliant 'file.mode' field.
// Mode of the file in octal representation.
func (File) Mode(value string) zapcore.Field {
	return String("file.mode", value)
}

// Type create the ECS compliant 'file.type' field.
// File type (file, dir, or symlink).
func (File) Type(value string) zapcore.Field {
	return String("file.type", value)
}

// Inode create the ECS compliant 'file.inode' field.
// Inode representing the file in the filesystem.
func (File) Inode(value string) zapcore.Field {
	return String("file.inode", value)
}

// Owner create the ECS compliant 'file.owner' field.
// File owner's username.
func (File) Owner(value string) zapcore.Field {
	return String("file.owner", value)
}

// Accessed create the ECS compliant 'file.accessed' field.
// Last time the file was accessed. Note that not all filesystems keep
// track of access time.
func (File) Accessed(value time.Time) zapcore.Field {
	return Time("file.accessed", value)
}

// Path create the ECS compliant 'file.path' field.
// Full path to the file, including the file name. It should include the
// drive letter, when appropriate.
func (File) Path(value string) zapcore.Field {
	return String("file.path", value)
}

// ## file.code_signature fields

// Status create the ECS compliant 'file.code_signature.status' field.
// Additional information about the certificate status. This is useful for
// logging cryptographic errors with the certificate validity or trust
// status. Leave unpopulated if the validity or trust of the certificate
// was unchecked.
func (FileCodeSignature) Status(value string) zapcore.Field {
	return String("file.code_signature.status", value)
}

// SubjectName create the ECS compliant 'file.code_signature.subject_name' field.
// Subject name of the code signer
func (FileCodeSignature) SubjectName(value string) zapcore.Field {
	return String("file.code_signature.subject_name", value)
}

// Valid create the ECS compliant 'file.code_signature.valid' field.
// Boolean to capture if the digital signature is verified against the
// binary content. Leave unpopulated if a certificate was unchecked.
func (FileCodeSignature) Valid(value bool) zapcore.Field {
	return Bool("file.code_signature.valid", value)
}

// Exists create the ECS compliant 'file.code_signature.exists' field.
// Boolean to capture if a signature is present.
func (FileCodeSignature) Exists(value bool) zapcore.Field {
	return Bool("file.code_signature.exists", value)
}

// Trusted create the ECS compliant 'file.code_signature.trusted' field.
// Stores the trust status of the certificate chain. Validating the trust
// of the certificate chain may be complicated, and this field should only
// be populated by tools that actively check the status.
func (FileCodeSignature) Trusted(value bool) zapcore.Field {
	return Bool("file.code_signature.trusted", value)
}

// ## file.hash fields

// Sha256 create the ECS compliant 'file.hash.sha256' field.
// SHA256 hash.
func (FileHash) Sha256(value string) zapcore.Field {
	return String("file.hash.sha256", value)
}

// Md5 create the ECS compliant 'file.hash.md5' field.
// MD5 hash.
func (FileHash) Md5(value string) zapcore.Field {
	return String("file.hash.md5", value)
}

// Sha1 create the ECS compliant 'file.hash.sha1' field.
// SHA1 hash.
func (FileHash) Sha1(value string) zapcore.Field {
	return String("file.hash.sha1", value)
}

// Sha512 create the ECS compliant 'file.hash.sha512' field.
// SHA512 hash.
func (FileHash) Sha512(value string) zapcore.Field {
	return String("file.hash.sha512", value)
}

// ## file.pe fields

// OriginalFileName create the ECS compliant 'file.pe.original_file_name' field.
// Internal name of the file, provided at compile-time.
func (FilePe) OriginalFileName(value string) zapcore.Field {
	return String("file.pe.original_file_name", value)
}

// Company create the ECS compliant 'file.pe.company' field.
// Internal company name of the file, provided at compile-time.
func (FilePe) Company(value string) zapcore.Field {
	return String("file.pe.company", value)
}

// Description create the ECS compliant 'file.pe.description' field.
// Internal description of the file, provided at compile-time.
func (FilePe) Description(value string) zapcore.Field {
	return String("file.pe.description", value)
}

// FileVersion create the ECS compliant 'file.pe.file_version' field.
// Internal version of the file, provided at compile-time.
func (FilePe) FileVersion(value string) zapcore.Field {
	return String("file.pe.file_version", value)
}

// Product create the ECS compliant 'file.pe.product' field.
// Internal product name of the file, provided at compile-time.
func (FilePe) Product(value string) zapcore.Field {
	return String("file.pe.product", value)
}

// ## geo fields

// ContinentName create the ECS compliant 'geo.continent_name' field.
// Name of the continent.
func (Geo) ContinentName(value string) zapcore.Field {
	return String("geo.continent_name", value)
}

// RegionName create the ECS compliant 'geo.region_name' field.
// Region name.
func (Geo) RegionName(value string) zapcore.Field {
	return String("geo.region_name", value)
}

// Location create the ECS compliant 'geo.location' field.
// Longitude and latitude.
func (Geo) Location(value string) zapcore.Field {
	return String("geo.location", value)
}

// CountryIsoCode create the ECS compliant 'geo.country_iso_code' field.
// Country ISO code.
func (Geo) CountryIsoCode(value string) zapcore.Field {
	return String("geo.country_iso_code", value)
}

// CountryName create the ECS compliant 'geo.country_name' field.
// Country name.
func (Geo) CountryName(value string) zapcore.Field {
	return String("geo.country_name", value)
}

// RegionIsoCode create the ECS compliant 'geo.region_iso_code' field.
// Region ISO code.
func (Geo) RegionIsoCode(value string) zapcore.Field {
	return String("geo.region_iso_code", value)
}

// CityName create the ECS compliant 'geo.city_name' field.
// City name.
func (Geo) CityName(value string) zapcore.Field {
	return String("geo.city_name", value)
}

// Name create the ECS compliant 'geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (Geo) Name(value string) zapcore.Field {
	return String("geo.name", value)
}

// ## group fields

// Domain create the ECS compliant 'group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (Group) Domain(value string) zapcore.Field {
	return String("group.domain", value)
}

// Name create the ECS compliant 'group.name' field.
// Name of the group.
func (Group) Name(value string) zapcore.Field {
	return String("group.name", value)
}

// ID create the ECS compliant 'group.id' field.
// Unique identifier for the group on the system/platform.
func (Group) ID(value string) zapcore.Field {
	return String("group.id", value)
}

// ## hash fields

// Sha1 create the ECS compliant 'hash.sha1' field.
// SHA1 hash.
func (Hash) Sha1(value string) zapcore.Field {
	return String("hash.sha1", value)
}

// Sha256 create the ECS compliant 'hash.sha256' field.
// SHA256 hash.
func (Hash) Sha256(value string) zapcore.Field {
	return String("hash.sha256", value)
}

// Sha512 create the ECS compliant 'hash.sha512' field.
// SHA512 hash.
func (Hash) Sha512(value string) zapcore.Field {
	return String("hash.sha512", value)
}

// Md5 create the ECS compliant 'hash.md5' field.
// MD5 hash.
func (Hash) Md5(value string) zapcore.Field {
	return String("hash.md5", value)
}

// ## host fields

// Architecture create the ECS compliant 'host.architecture' field.
// Operating system architecture.
func (Host) Architecture(value string) zapcore.Field {
	return String("host.architecture", value)
}

// Domain create the ECS compliant 'host.domain' field.
// Name of the domain of which the host is a member. For example, on
// Windows this could be the host's Active Directory domain or NetBIOS
// domain name. For Linux this could be the domain of the host's LDAP
// provider.
func (Host) Domain(value string) zapcore.Field {
	return String("host.domain", value)
}

// Name create the ECS compliant 'host.name' field.
// Name of the host. It can contain what `hostname` returns on Unix
// systems, the fully qualified domain name, or a name specified by the
// user. The sender decides which value to use.
func (Host) Name(value string) zapcore.Field {
	return String("host.name", value)
}

// Type create the ECS compliant 'host.type' field.
// Type of host. For Cloud providers this can be the machine type like
// `t2.medium`. If vm, this could be the container, for example, or other
// information meaningful in your environment.
func (Host) Type(value string) zapcore.Field {
	return String("host.type", value)
}

// Hostname create the ECS compliant 'host.hostname' field.
// Hostname of the host. It normally contains what the `hostname` command
// returns on the host machine.
func (Host) Hostname(value string) zapcore.Field {
	return String("host.hostname", value)
}

// ID create the ECS compliant 'host.id' field.
// Unique host id. As hostname is not always unique, use values that are
// meaningful in your environment. Example: The current usage of
// `beat.name`.
func (Host) ID(value string) zapcore.Field {
	return String("host.id", value)
}

// Uptime create the ECS compliant 'host.uptime' field.
// Seconds the host has been up.
func (Host) Uptime(value int64) zapcore.Field {
	return Int64("host.uptime", value)
}

// MAC create the ECS compliant 'host.mac' field.
// Host mac addresses.
func (Host) MAC(value string) zapcore.Field {
	return String("host.mac", value)
}

// IP create the ECS compliant 'host.ip' field.
// Host ip addresses.
func (Host) IP(value string) zapcore.Field {
	return String("host.ip", value)
}

// ## host.geo fields

// CountryName create the ECS compliant 'host.geo.country_name' field.
// Country name.
func (HostGeo) CountryName(value string) zapcore.Field {
	return String("host.geo.country_name", value)
}

// Location create the ECS compliant 'host.geo.location' field.
// Longitude and latitude.
func (HostGeo) Location(value string) zapcore.Field {
	return String("host.geo.location", value)
}

// CountryIsoCode create the ECS compliant 'host.geo.country_iso_code' field.
// Country ISO code.
func (HostGeo) CountryIsoCode(value string) zapcore.Field {
	return String("host.geo.country_iso_code", value)
}

// ContinentName create the ECS compliant 'host.geo.continent_name' field.
// Name of the continent.
func (HostGeo) ContinentName(value string) zapcore.Field {
	return String("host.geo.continent_name", value)
}

// CityName create the ECS compliant 'host.geo.city_name' field.
// City name.
func (HostGeo) CityName(value string) zapcore.Field {
	return String("host.geo.city_name", value)
}

// RegionName create the ECS compliant 'host.geo.region_name' field.
// Region name.
func (HostGeo) RegionName(value string) zapcore.Field {
	return String("host.geo.region_name", value)
}

// Name create the ECS compliant 'host.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (HostGeo) Name(value string) zapcore.Field {
	return String("host.geo.name", value)
}

// RegionIsoCode create the ECS compliant 'host.geo.region_iso_code' field.
// Region ISO code.
func (HostGeo) RegionIsoCode(value string) zapcore.Field {
	return String("host.geo.region_iso_code", value)
}

// ## host.os fields

// Kernel create the ECS compliant 'host.os.kernel' field.
// Operating system kernel version as a raw string.
func (HostOS) Kernel(value string) zapcore.Field {
	return String("host.os.kernel", value)
}

// Version create the ECS compliant 'host.os.version' field.
// Operating system version as a raw string.
func (HostOS) Version(value string) zapcore.Field {
	return String("host.os.version", value)
}

// Full create the ECS compliant 'host.os.full' field.
// Operating system name, including the version or code name.
func (HostOS) Full(value string) zapcore.Field {
	return String("host.os.full", value)
}

// Name create the ECS compliant 'host.os.name' field.
// Operating system name, without the version.
func (HostOS) Name(value string) zapcore.Field {
	return String("host.os.name", value)
}

// Family create the ECS compliant 'host.os.family' field.
// OS family (such as redhat, debian, freebsd, windows).
func (HostOS) Family(value string) zapcore.Field {
	return String("host.os.family", value)
}

// Platform create the ECS compliant 'host.os.platform' field.
// Operating system platform (such centos, ubuntu, windows).
func (HostOS) Platform(value string) zapcore.Field {
	return String("host.os.platform", value)
}

// ## host.user fields

// ID create the ECS compliant 'host.user.id' field.
// Unique identifiers of the user.
func (HostUser) ID(value string) zapcore.Field {
	return String("host.user.id", value)
}

// FullName create the ECS compliant 'host.user.full_name' field.
// User's full name, if available.
func (HostUser) FullName(value string) zapcore.Field {
	return String("host.user.full_name", value)
}

// Domain create the ECS compliant 'host.user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (HostUser) Domain(value string) zapcore.Field {
	return String("host.user.domain", value)
}

// Email create the ECS compliant 'host.user.email' field.
// User email address.
func (HostUser) Email(value string) zapcore.Field {
	return String("host.user.email", value)
}

// Hash create the ECS compliant 'host.user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (HostUser) Hash(value string) zapcore.Field {
	return String("host.user.hash", value)
}

// Name create the ECS compliant 'host.user.name' field.
// Short name or login of the user.
func (HostUser) Name(value string) zapcore.Field {
	return String("host.user.name", value)
}

// ## host.user.group fields

// Domain create the ECS compliant 'host.user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (HostUserGroup) Domain(value string) zapcore.Field {
	return String("host.user.group.domain", value)
}

// Name create the ECS compliant 'host.user.group.name' field.
// Name of the group.
func (HostUserGroup) Name(value string) zapcore.Field {
	return String("host.user.group.name", value)
}

// ID create the ECS compliant 'host.user.group.id' field.
// Unique identifier for the group on the system/platform.
func (HostUserGroup) ID(value string) zapcore.Field {
	return String("host.user.group.id", value)
}

// ## http fields

// Version create the ECS compliant 'http.version' field.
// HTTP version.
func (HTTP) Version(value string) zapcore.Field {
	return String("http.version", value)
}

// ## http.request fields

// Referrer create the ECS compliant 'http.request.referrer' field.
// Referrer for this HTTP request.
func (HTTPRequest) Referrer(value string) zapcore.Field {
	return String("http.request.referrer", value)
}

// Bytes create the ECS compliant 'http.request.bytes' field.
// Total size in bytes of the request (body and headers).
func (HTTPRequest) Bytes(value int64) zapcore.Field {
	return Int64("http.request.bytes", value)
}

// Method create the ECS compliant 'http.request.method' field.
// HTTP request method. The field value must be normalized to lowercase
// for querying. See the documentation section "Implementing ECS".
func (HTTPRequest) Method(value string) zapcore.Field {
	return String("http.request.method", value)
}

// ## http.request.body fields

// Bytes create the ECS compliant 'http.request.body.bytes' field.
// Size in bytes of the request body.
func (HTTPRequestBody) Bytes(value int64) zapcore.Field {
	return Int64("http.request.body.bytes", value)
}

// Content create the ECS compliant 'http.request.body.content' field.
// The full HTTP request body.
func (HTTPRequestBody) Content(value string) zapcore.Field {
	return String("http.request.body.content", value)
}

// ## http.response fields

// StatusCode create the ECS compliant 'http.response.status_code' field.
// HTTP response status code.
func (HTTPResponse) StatusCode(value int64) zapcore.Field {
	return Int64("http.response.status_code", value)
}

// Bytes create the ECS compliant 'http.response.bytes' field.
// Total size in bytes of the response (body and headers).
func (HTTPResponse) Bytes(value int64) zapcore.Field {
	return Int64("http.response.bytes", value)
}

// ## http.response.body fields

// Bytes create the ECS compliant 'http.response.body.bytes' field.
// Size in bytes of the response body.
func (HTTPResponseBody) Bytes(value int64) zapcore.Field {
	return Int64("http.response.body.bytes", value)
}

// Content create the ECS compliant 'http.response.body.content' field.
// The full HTTP response body.
func (HTTPResponseBody) Content(value string) zapcore.Field {
	return String("http.response.body.content", value)
}

// ## interface fields

// Name create the ECS compliant 'interface.name' field.
// Interface name as reported by the system.
func (Interface) Name(value string) zapcore.Field {
	return String("interface.name", value)
}

// ID create the ECS compliant 'interface.id' field.
// Interface ID as reported by an observer (typically SNMP interface ID).
func (Interface) ID(value string) zapcore.Field {
	return String("interface.id", value)
}

// Alias create the ECS compliant 'interface.alias' field.
// Interface alias as reported by the system, typically used in firewall
// implementations for e.g. inside, outside, or dmz logical interface
// naming.
func (Interface) Alias(value string) zapcore.Field {
	return String("interface.alias", value)
}

// ## log fields

// Level create the ECS compliant 'log.level' field.
// Original log level of the log event. If the source of the event
// provides a log level or textual severity, this is the one that goes in
// `log.level`. If your source doesn't specify one, you may put your event
// transport's severity here (e.g. Syslog severity). Some examples are
// `warn`, `err`, `i`, `informational`.
func (Log) Level(value string) zapcore.Field {
	return String("log.level", value)
}

// Logger create the ECS compliant 'log.logger' field.
// The name of the logger inside an application. This is usually the name
// of the class which initialized the logger, or can be a custom name.
func (Log) Logger(value string) zapcore.Field {
	return String("log.logger", value)
}

// Original create the ECS compliant 'log.original' field.
// This is the original log message and contains the full log message
// before splitting it up in multiple parts. In contrast to the `message`
// field which can contain an extracted part of the log message, this
// field contains the original, full log message. It can have already some
// modifications applied like encoding or new lines removed to clean up
// the log message. This field is not indexed and doc_values are disabled
// so it can't be queried but the value can be retrieved from `_source`.
func (Log) Original(value string) zapcore.Field {
	return String("log.original", value)
}

// ## log.origin fields

// Function create the ECS compliant 'log.origin.function' field.
// The name of the function or method which originated the log event.
func (LogOrigin) Function(value string) zapcore.Field {
	return String("log.origin.function", value)
}

// ## log.origin.file fields

// Line create the ECS compliant 'log.origin.file.line' field.
// The line number of the file containing the source code which originated
// the log event.
func (LogOriginFile) Line(value int) zapcore.Field {
	return Int("log.origin.file.line", value)
}

// Name create the ECS compliant 'log.origin.file.name' field.
// The name of the file containing the source code which originated the
// log event. Note that this is not the name of the log file.
func (LogOriginFile) Name(value string) zapcore.Field {
	return String("log.origin.file.name", value)
}

// ## log.syslog fields

// Priority create the ECS compliant 'log.syslog.priority' field.
// Syslog numeric priority of the event, if available. According to RFCs
// 5424 and 3164, the priority is 8 * facility + severity. This number is
// therefore expected to contain a value between 0 and 191.
func (LogSyslog) Priority(value int64) zapcore.Field {
	return Int64("log.syslog.priority", value)
}

// ## log.syslog.facility fields

// Name create the ECS compliant 'log.syslog.facility.name' field.
// The Syslog text-based facility of the log event, if available.
func (LogSyslogFacility) Name(value string) zapcore.Field {
	return String("log.syslog.facility.name", value)
}

// Code create the ECS compliant 'log.syslog.facility.code' field.
// The Syslog numeric facility of the log event, if available. According
// to RFCs 5424 and 3164, this value should be an integer between 0 and
// 23.
func (LogSyslogFacility) Code(value int64) zapcore.Field {
	return Int64("log.syslog.facility.code", value)
}

// ## log.syslog.severity fields

// Code create the ECS compliant 'log.syslog.severity.code' field.
// The Syslog numeric severity of the log event, if available. If the
// event source publishing via Syslog provides a different numeric
// severity value (e.g. firewall, IDS), your source's numeric severity
// should go to `event.severity`. If the event source does not specify a
// distinct severity, you can optionally copy the Syslog severity to
// `event.severity`.
func (LogSyslogSeverity) Code(value int64) zapcore.Field {
	return Int64("log.syslog.severity.code", value)
}

// Name create the ECS compliant 'log.syslog.severity.name' field.
// The Syslog numeric severity of the log event, if available. If the
// event source publishing via Syslog provides a different severity value
// (e.g. firewall, IDS), your source's text severity should go to
// `log.level`. If the event source does not specify a distinct severity,
// you can optionally copy the Syslog severity to `log.level`.
func (LogSyslogSeverity) Name(value string) zapcore.Field {
	return String("log.syslog.severity.name", value)
}

// ## network fields

// Direction create the ECS compliant 'network.direction' field.
// Direction of the network traffic. Recommended values are:   * inbound
// * outbound   * internal   * external   * unknown  When mapping events
// from a host-based monitoring context, populate this field from the
// host's point of view. When mapping events from a network or
// perimeter-based monitoring context, populate this field from the point
// of view of your network perimeter.
func (Network) Direction(value string) zapcore.Field {
	return String("network.direction", value)
}

// CommunityID create the ECS compliant 'network.community_id' field.
// A hash of source and destination IPs and ports, as well as the protocol
// used in a communication. This is a tool-agnostic standard to identify
// flows. Learn more at https://github.com/corelight/community-id-spec.
func (Network) CommunityID(value string) zapcore.Field {
	return String("network.community_id", value)
}

// Transport create the ECS compliant 'network.transport' field.
// Same as network.iana_number, but instead using the Keyword name of the
// transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be
// normalized to lowercase for querying. See the documentation section
// "Implementing ECS".
func (Network) Transport(value string) zapcore.Field {
	return String("network.transport", value)
}

// Bytes create the ECS compliant 'network.bytes' field.
// Total bytes transferred in both directions. If `source.bytes` and
// `destination.bytes` are known, `network.bytes` is their sum.
func (Network) Bytes(value int64) zapcore.Field {
	return Int64("network.bytes", value)
}

// Type create the ECS compliant 'network.type' field.
// In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec,
// pim, etc The field value must be normalized to lowercase for querying.
// See the documentation section "Implementing ECS".
func (Network) Type(value string) zapcore.Field {
	return String("network.type", value)
}

// ForwardedIP create the ECS compliant 'network.forwarded_ip' field.
// Host IP address when the source IP address is the proxy.
func (Network) ForwardedIP(value string) zapcore.Field {
	return String("network.forwarded_ip", value)
}

// Application create the ECS compliant 'network.application' field.
// A name given to an application level protocol. This can be arbitrarily
// assigned for things like microservices, but also apply to things like
// skype, icq, facebook, twitter. This would be used in situations where
// the vendor or service can be decoded such as from the source/dest IP
// owners, ports, or wire format. The field value must be normalized to
// lowercase for querying. See the documentation section "Implementing
// ECS".
func (Network) Application(value string) zapcore.Field {
	return String("network.application", value)
}

// Packets create the ECS compliant 'network.packets' field.
// Total packets transferred in both directions. If `source.packets` and
// `destination.packets` are known, `network.packets` is their sum.
func (Network) Packets(value int64) zapcore.Field {
	return Int64("network.packets", value)
}

// IANANumber create the ECS compliant 'network.iana_number' field.
// IANA Protocol Number
// (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).
// Standardized list of protocols. This aligns well with NetFlow and sFlow
// related logs which use the IANA Protocol Number.
func (Network) IANANumber(value string) zapcore.Field {
	return String("network.iana_number", value)
}

// Name create the ECS compliant 'network.name' field.
// Name given by operators to sections of their network.
func (Network) Name(value string) zapcore.Field {
	return String("network.name", value)
}

// Protocol create the ECS compliant 'network.protocol' field.
// L7 Network protocol name. ex. http, lumberjack, transport protocol. The
// field value must be normalized to lowercase for querying. See the
// documentation section "Implementing ECS".
func (Network) Protocol(value string) zapcore.Field {
	return String("network.protocol", value)
}

// ## network.inner fields

// ## network.inner.vlan fields

// Name create the ECS compliant 'network.inner.vlan.name' field.
// Optional VLAN name as reported by the observer.
func (NetworkInnerVlan) Name(value string) zapcore.Field {
	return String("network.inner.vlan.name", value)
}

// ID create the ECS compliant 'network.inner.vlan.id' field.
// VLAN ID as reported by the observer.
func (NetworkInnerVlan) ID(value string) zapcore.Field {
	return String("network.inner.vlan.id", value)
}

// ## network.vlan fields

// ID create the ECS compliant 'network.vlan.id' field.
// VLAN ID as reported by the observer.
func (NetworkVlan) ID(value string) zapcore.Field {
	return String("network.vlan.id", value)
}

// Name create the ECS compliant 'network.vlan.name' field.
// Optional VLAN name as reported by the observer.
func (NetworkVlan) Name(value string) zapcore.Field {
	return String("network.vlan.name", value)
}

// ## observer fields

// Hostname create the ECS compliant 'observer.hostname' field.
// Hostname of the observer.
func (Observer) Hostname(value string) zapcore.Field {
	return String("observer.hostname", value)
}

// Product create the ECS compliant 'observer.product' field.
// The product name of the observer.
func (Observer) Product(value string) zapcore.Field {
	return String("observer.product", value)
}

// IP create the ECS compliant 'observer.ip' field.
// IP addresses of the observer.
func (Observer) IP(value string) zapcore.Field {
	return String("observer.ip", value)
}

// MAC create the ECS compliant 'observer.mac' field.
// MAC addresses of the observer
func (Observer) MAC(value string) zapcore.Field {
	return String("observer.mac", value)
}

// Type create the ECS compliant 'observer.type' field.
// The type of the observer the data is coming from. There is no
// predefined list of observer types. Some examples are `forwarder`,
// `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`.
func (Observer) Type(value string) zapcore.Field {
	return String("observer.type", value)
}

// Vendor create the ECS compliant 'observer.vendor' field.
// Vendor name of the observer.
func (Observer) Vendor(value string) zapcore.Field {
	return String("observer.vendor", value)
}

// Version create the ECS compliant 'observer.version' field.
// Observer version.
func (Observer) Version(value string) zapcore.Field {
	return String("observer.version", value)
}

// Name create the ECS compliant 'observer.name' field.
// Custom name of the observer. This is a name that can be given to an
// observer. This can be helpful for example if multiple firewalls of the
// same model are used in an organization. If no custom name is needed,
// the field can be left empty.
func (Observer) Name(value string) zapcore.Field {
	return String("observer.name", value)
}

// SerialNumber create the ECS compliant 'observer.serial_number' field.
// Observer serial number.
func (Observer) SerialNumber(value string) zapcore.Field {
	return String("observer.serial_number", value)
}

// ## observer.egress fields

// Zone create the ECS compliant 'observer.egress.zone' field.
// Network zone of outbound traffic as reported by the observer to
// categorize the destination area of egress  traffic, e.g. Internal,
// External, DMZ, HR, Legal, etc.
func (ObserverEgress) Zone(value string) zapcore.Field {
	return String("observer.egress.zone", value)
}

// ## observer.egress.interface fields

// ID create the ECS compliant 'observer.egress.interface.id' field.
// Interface ID as reported by an observer (typically SNMP interface ID).
func (ObserverEgressInterface) ID(value string) zapcore.Field {
	return String("observer.egress.interface.id", value)
}

// Name create the ECS compliant 'observer.egress.interface.name' field.
// Interface name as reported by the system.
func (ObserverEgressInterface) Name(value string) zapcore.Field {
	return String("observer.egress.interface.name", value)
}

// Alias create the ECS compliant 'observer.egress.interface.alias' field.
// Interface alias as reported by the system, typically used in firewall
// implementations for e.g. inside, outside, or dmz logical interface
// naming.
func (ObserverEgressInterface) Alias(value string) zapcore.Field {
	return String("observer.egress.interface.alias", value)
}

// ## observer.egress.vlan fields

// ID create the ECS compliant 'observer.egress.vlan.id' field.
// VLAN ID as reported by the observer.
func (ObserverEgressVlan) ID(value string) zapcore.Field {
	return String("observer.egress.vlan.id", value)
}

// Name create the ECS compliant 'observer.egress.vlan.name' field.
// Optional VLAN name as reported by the observer.
func (ObserverEgressVlan) Name(value string) zapcore.Field {
	return String("observer.egress.vlan.name", value)
}

// ## observer.geo fields

// RegionName create the ECS compliant 'observer.geo.region_name' field.
// Region name.
func (ObserverGeo) RegionName(value string) zapcore.Field {
	return String("observer.geo.region_name", value)
}

// Name create the ECS compliant 'observer.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (ObserverGeo) Name(value string) zapcore.Field {
	return String("observer.geo.name", value)
}

// Location create the ECS compliant 'observer.geo.location' field.
// Longitude and latitude.
func (ObserverGeo) Location(value string) zapcore.Field {
	return String("observer.geo.location", value)
}

// CountryName create the ECS compliant 'observer.geo.country_name' field.
// Country name.
func (ObserverGeo) CountryName(value string) zapcore.Field {
	return String("observer.geo.country_name", value)
}

// RegionIsoCode create the ECS compliant 'observer.geo.region_iso_code' field.
// Region ISO code.
func (ObserverGeo) RegionIsoCode(value string) zapcore.Field {
	return String("observer.geo.region_iso_code", value)
}

// CityName create the ECS compliant 'observer.geo.city_name' field.
// City name.
func (ObserverGeo) CityName(value string) zapcore.Field {
	return String("observer.geo.city_name", value)
}

// ContinentName create the ECS compliant 'observer.geo.continent_name' field.
// Name of the continent.
func (ObserverGeo) ContinentName(value string) zapcore.Field {
	return String("observer.geo.continent_name", value)
}

// CountryIsoCode create the ECS compliant 'observer.geo.country_iso_code' field.
// Country ISO code.
func (ObserverGeo) CountryIsoCode(value string) zapcore.Field {
	return String("observer.geo.country_iso_code", value)
}

// ## observer.ingress fields

// Zone create the ECS compliant 'observer.ingress.zone' field.
// Network zone of incoming traffic as reported by the observer to
// categorize the source area of ingress  traffic. e.g. internal,
// External, DMZ, HR, Legal, etc.
func (ObserverIngress) Zone(value string) zapcore.Field {
	return String("observer.ingress.zone", value)
}

// ## observer.ingress.interface fields

// ID create the ECS compliant 'observer.ingress.interface.id' field.
// Interface ID as reported by an observer (typically SNMP interface ID).
func (ObserverIngressInterface) ID(value string) zapcore.Field {
	return String("observer.ingress.interface.id", value)
}

// Alias create the ECS compliant 'observer.ingress.interface.alias' field.
// Interface alias as reported by the system, typically used in firewall
// implementations for e.g. inside, outside, or dmz logical interface
// naming.
func (ObserverIngressInterface) Alias(value string) zapcore.Field {
	return String("observer.ingress.interface.alias", value)
}

// Name create the ECS compliant 'observer.ingress.interface.name' field.
// Interface name as reported by the system.
func (ObserverIngressInterface) Name(value string) zapcore.Field {
	return String("observer.ingress.interface.name", value)
}

// ## observer.ingress.vlan fields

// ID create the ECS compliant 'observer.ingress.vlan.id' field.
// VLAN ID as reported by the observer.
func (ObserverIngressVlan) ID(value string) zapcore.Field {
	return String("observer.ingress.vlan.id", value)
}

// Name create the ECS compliant 'observer.ingress.vlan.name' field.
// Optional VLAN name as reported by the observer.
func (ObserverIngressVlan) Name(value string) zapcore.Field {
	return String("observer.ingress.vlan.name", value)
}

// ## observer.os fields

// Version create the ECS compliant 'observer.os.version' field.
// Operating system version as a raw string.
func (ObserverOS) Version(value string) zapcore.Field {
	return String("observer.os.version", value)
}

// Family create the ECS compliant 'observer.os.family' field.
// OS family (such as redhat, debian, freebsd, windows).
func (ObserverOS) Family(value string) zapcore.Field {
	return String("observer.os.family", value)
}

// Platform create the ECS compliant 'observer.os.platform' field.
// Operating system platform (such centos, ubuntu, windows).
func (ObserverOS) Platform(value string) zapcore.Field {
	return String("observer.os.platform", value)
}

// Name create the ECS compliant 'observer.os.name' field.
// Operating system name, without the version.
func (ObserverOS) Name(value string) zapcore.Field {
	return String("observer.os.name", value)
}

// Full create the ECS compliant 'observer.os.full' field.
// Operating system name, including the version or code name.
func (ObserverOS) Full(value string) zapcore.Field {
	return String("observer.os.full", value)
}

// Kernel create the ECS compliant 'observer.os.kernel' field.
// Operating system kernel version as a raw string.
func (ObserverOS) Kernel(value string) zapcore.Field {
	return String("observer.os.kernel", value)
}

// ## organization fields

// Name create the ECS compliant 'organization.name' field.
// Organization name.
func (Organization) Name(value string) zapcore.Field {
	return String("organization.name", value)
}

// ID create the ECS compliant 'organization.id' field.
// Unique identifier for the organization.
func (Organization) ID(value string) zapcore.Field {
	return String("organization.id", value)
}

// ## os fields

// Platform create the ECS compliant 'os.platform' field.
// Operating system platform (such centos, ubuntu, windows).
func (OS) Platform(value string) zapcore.Field {
	return String("os.platform", value)
}

// Kernel create the ECS compliant 'os.kernel' field.
// Operating system kernel version as a raw string.
func (OS) Kernel(value string) zapcore.Field {
	return String("os.kernel", value)
}

// Name create the ECS compliant 'os.name' field.
// Operating system name, without the version.
func (OS) Name(value string) zapcore.Field {
	return String("os.name", value)
}

// Family create the ECS compliant 'os.family' field.
// OS family (such as redhat, debian, freebsd, windows).
func (OS) Family(value string) zapcore.Field {
	return String("os.family", value)
}

// Full create the ECS compliant 'os.full' field.
// Operating system name, including the version or code name.
func (OS) Full(value string) zapcore.Field {
	return String("os.full", value)
}

// Version create the ECS compliant 'os.version' field.
// Operating system version as a raw string.
func (OS) Version(value string) zapcore.Field {
	return String("os.version", value)
}

// ## package fields

// Description create the ECS compliant 'package.description' field.
// Description of the package.
func (Package) Description(value string) zapcore.Field {
	return String("package.description", value)
}

// Architecture create the ECS compliant 'package.architecture' field.
// Package architecture.
func (Package) Architecture(value string) zapcore.Field {
	return String("package.architecture", value)
}

// BuildVersion create the ECS compliant 'package.build_version' field.
// Additional information about the build version of the installed
// package. For example use the commit SHA of a non-released package.
func (Package) BuildVersion(value string) zapcore.Field {
	return String("package.build_version", value)
}

// InstallScope create the ECS compliant 'package.install_scope' field.
// Indicating how the package was installed, e.g. user-local, global.
func (Package) InstallScope(value string) zapcore.Field {
	return String("package.install_scope", value)
}

// Name create the ECS compliant 'package.name' field.
// Package name
func (Package) Name(value string) zapcore.Field {
	return String("package.name", value)
}

// Reference create the ECS compliant 'package.reference' field.
// Home page or reference URL of the software in this package, if
// available.
func (Package) Reference(value string) zapcore.Field {
	return String("package.reference", value)
}

// Size create the ECS compliant 'package.size' field.
// Package size in bytes.
func (Package) Size(value int64) zapcore.Field {
	return Int64("package.size", value)
}

// Version create the ECS compliant 'package.version' field.
// Package version
func (Package) Version(value string) zapcore.Field {
	return String("package.version", value)
}

// Path create the ECS compliant 'package.path' field.
// Path where the package is installed.
func (Package) Path(value string) zapcore.Field {
	return String("package.path", value)
}

// Checksum create the ECS compliant 'package.checksum' field.
// Checksum of the installed package for verification.
func (Package) Checksum(value string) zapcore.Field {
	return String("package.checksum", value)
}

// License create the ECS compliant 'package.license' field.
// License under which the package was released. Use a short name, e.g.
// the license identifier from SPDX License List where possible
// (https://spdx.org/licenses/).
func (Package) License(value string) zapcore.Field {
	return String("package.license", value)
}

// Type create the ECS compliant 'package.type' field.
// Type of package. This should contain the package file type, rather than
// the package manager name. Examples: rpm, dpkg, brew, npm, gem, nupkg,
// jar.
func (Package) Type(value string) zapcore.Field {
	return String("package.type", value)
}

// Installed create the ECS compliant 'package.installed' field.
// Time when package was installed.
func (Package) Installed(value time.Time) zapcore.Field {
	return Time("package.installed", value)
}

// ## pe fields

// Description create the ECS compliant 'pe.description' field.
// Internal description of the file, provided at compile-time.
func (Pe) Description(value string) zapcore.Field {
	return String("pe.description", value)
}

// Company create the ECS compliant 'pe.company' field.
// Internal company name of the file, provided at compile-time.
func (Pe) Company(value string) zapcore.Field {
	return String("pe.company", value)
}

// FileVersion create the ECS compliant 'pe.file_version' field.
// Internal version of the file, provided at compile-time.
func (Pe) FileVersion(value string) zapcore.Field {
	return String("pe.file_version", value)
}

// Product create the ECS compliant 'pe.product' field.
// Internal product name of the file, provided at compile-time.
func (Pe) Product(value string) zapcore.Field {
	return String("pe.product", value)
}

// OriginalFileName create the ECS compliant 'pe.original_file_name' field.
// Internal name of the file, provided at compile-time.
func (Pe) OriginalFileName(value string) zapcore.Field {
	return String("pe.original_file_name", value)
}

// ## process fields

// Pgid create the ECS compliant 'process.pgid' field.
// Identifier of the group of processes the process belongs to.
func (Process) Pgid(value int64) zapcore.Field {
	return Int64("process.pgid", value)
}

// ExitCode create the ECS compliant 'process.exit_code' field.
// The exit code of the process, if this is a termination event. The field
// should be absent if there is no exit code for the event (e.g. process
// start).
func (Process) ExitCode(value int64) zapcore.Field {
	return Int64("process.exit_code", value)
}

// Start create the ECS compliant 'process.start' field.
// The time the process started.
func (Process) Start(value time.Time) zapcore.Field {
	return Time("process.start", value)
}

// PPID create the ECS compliant 'process.ppid' field.
// Parent process' pid.
func (Process) PPID(value int64) zapcore.Field {
	return Int64("process.ppid", value)
}

// WorkingDirectory create the ECS compliant 'process.working_directory' field.
// The working directory of the process.
func (Process) WorkingDirectory(value string) zapcore.Field {
	return String("process.working_directory", value)
}

// Uptime create the ECS compliant 'process.uptime' field.
// Seconds the process has been up.
func (Process) Uptime(value int64) zapcore.Field {
	return Int64("process.uptime", value)
}

// CommandLine create the ECS compliant 'process.command_line' field.
// Full command line that started the process, including the absolute path
// to the executable, and all arguments. Some arguments may be filtered to
// protect sensitive information.
func (Process) CommandLine(value string) zapcore.Field {
	return String("process.command_line", value)
}

// EntityID create the ECS compliant 'process.entity_id' field.
// Unique identifier for the process. The implementation of this is
// specified by the data source, but some examples of what could be used
// here are a process-generated UUID, Sysmon Process GUIDs, or a hash of
// some uniquely identifying components of a process. Constructing a
// globally unique identifier is a common practice to mitigate PID reuse
// as well as to identify a specific process over time, across multiple
// monitored hosts.
func (Process) EntityID(value string) zapcore.Field {
	return String("process.entity_id", value)
}

// Title create the ECS compliant 'process.title' field.
// Process title. The proctitle, some times the same as process name. Can
// also be different: for example a browser setting its title to the web
// page currently opened.
func (Process) Title(value string) zapcore.Field {
	return String("process.title", value)
}

// Executable create the ECS compliant 'process.executable' field.
// Absolute path to the process executable.
func (Process) Executable(value string) zapcore.Field {
	return String("process.executable", value)
}

// Args create the ECS compliant 'process.args' field.
// Array of process arguments, starting with the absolute path to the
// executable. May be filtered to protect sensitive information.
func (Process) Args(value string) zapcore.Field {
	return String("process.args", value)
}

// PID create the ECS compliant 'process.pid' field.
// Process id.
func (Process) PID(value int64) zapcore.Field {
	return Int64("process.pid", value)
}

// Name create the ECS compliant 'process.name' field.
// Process name. Sometimes called program name or similar.
func (Process) Name(value string) zapcore.Field {
	return String("process.name", value)
}

// ArgsCount create the ECS compliant 'process.args_count' field.
// Length of the process.args array. This field can be useful for querying
// or performing bucket analysis on how many arguments were provided to
// start a process. More arguments may be an indication of suspicious
// activity.
func (Process) ArgsCount(value int64) zapcore.Field {
	return Int64("process.args_count", value)
}

// ## process.code_signature fields

// SubjectName create the ECS compliant 'process.code_signature.subject_name' field.
// Subject name of the code signer
func (ProcessCodeSignature) SubjectName(value string) zapcore.Field {
	return String("process.code_signature.subject_name", value)
}

// Exists create the ECS compliant 'process.code_signature.exists' field.
// Boolean to capture if a signature is present.
func (ProcessCodeSignature) Exists(value bool) zapcore.Field {
	return Bool("process.code_signature.exists", value)
}

// Status create the ECS compliant 'process.code_signature.status' field.
// Additional information about the certificate status. This is useful for
// logging cryptographic errors with the certificate validity or trust
// status. Leave unpopulated if the validity or trust of the certificate
// was unchecked.
func (ProcessCodeSignature) Status(value string) zapcore.Field {
	return String("process.code_signature.status", value)
}

// Valid create the ECS compliant 'process.code_signature.valid' field.
// Boolean to capture if the digital signature is verified against the
// binary content. Leave unpopulated if a certificate was unchecked.
func (ProcessCodeSignature) Valid(value bool) zapcore.Field {
	return Bool("process.code_signature.valid", value)
}

// Trusted create the ECS compliant 'process.code_signature.trusted' field.
// Stores the trust status of the certificate chain. Validating the trust
// of the certificate chain may be complicated, and this field should only
// be populated by tools that actively check the status.
func (ProcessCodeSignature) Trusted(value bool) zapcore.Field {
	return Bool("process.code_signature.trusted", value)
}

// ## process.hash fields

// Md5 create the ECS compliant 'process.hash.md5' field.
// MD5 hash.
func (ProcessHash) Md5(value string) zapcore.Field {
	return String("process.hash.md5", value)
}

// Sha256 create the ECS compliant 'process.hash.sha256' field.
// SHA256 hash.
func (ProcessHash) Sha256(value string) zapcore.Field {
	return String("process.hash.sha256", value)
}

// Sha1 create the ECS compliant 'process.hash.sha1' field.
// SHA1 hash.
func (ProcessHash) Sha1(value string) zapcore.Field {
	return String("process.hash.sha1", value)
}

// Sha512 create the ECS compliant 'process.hash.sha512' field.
// SHA512 hash.
func (ProcessHash) Sha512(value string) zapcore.Field {
	return String("process.hash.sha512", value)
}

// ## process.parent fields

// Uptime create the ECS compliant 'process.parent.uptime' field.
// Seconds the process has been up.
func (ProcessParent) Uptime(value int64) zapcore.Field {
	return Int64("process.parent.uptime", value)
}

// EntityID create the ECS compliant 'process.parent.entity_id' field.
// Unique identifier for the process. The implementation of this is
// specified by the data source, but some examples of what could be used
// here are a process-generated UUID, Sysmon Process GUIDs, or a hash of
// some uniquely identifying components of a process. Constructing a
// globally unique identifier is a common practice to mitigate PID reuse
// as well as to identify a specific process over time, across multiple
// monitored hosts.
func (ProcessParent) EntityID(value string) zapcore.Field {
	return String("process.parent.entity_id", value)
}

// PID create the ECS compliant 'process.parent.pid' field.
// Process id.
func (ProcessParent) PID(value int64) zapcore.Field {
	return Int64("process.parent.pid", value)
}

// ExitCode create the ECS compliant 'process.parent.exit_code' field.
// The exit code of the process, if this is a termination event. The field
// should be absent if there is no exit code for the event (e.g. process
// start).
func (ProcessParent) ExitCode(value int64) zapcore.Field {
	return Int64("process.parent.exit_code", value)
}

// PPID create the ECS compliant 'process.parent.ppid' field.
// Parent process' pid.
func (ProcessParent) PPID(value int64) zapcore.Field {
	return Int64("process.parent.ppid", value)
}

// WorkingDirectory create the ECS compliant 'process.parent.working_directory' field.
// The working directory of the process.
func (ProcessParent) WorkingDirectory(value string) zapcore.Field {
	return String("process.parent.working_directory", value)
}

// Name create the ECS compliant 'process.parent.name' field.
// Process name. Sometimes called program name or similar.
func (ProcessParent) Name(value string) zapcore.Field {
	return String("process.parent.name", value)
}

// Pgid create the ECS compliant 'process.parent.pgid' field.
// Identifier of the group of processes the process belongs to.
func (ProcessParent) Pgid(value int64) zapcore.Field {
	return Int64("process.parent.pgid", value)
}

// ArgsCount create the ECS compliant 'process.parent.args_count' field.
// Length of the process.args array. This field can be useful for querying
// or performing bucket analysis on how many arguments were provided to
// start a process. More arguments may be an indication of suspicious
// activity.
func (ProcessParent) ArgsCount(value int64) zapcore.Field {
	return Int64("process.parent.args_count", value)
}

// Args create the ECS compliant 'process.parent.args' field.
// Array of process arguments. May be filtered to protect sensitive
// information.
func (ProcessParent) Args(value string) zapcore.Field {
	return String("process.parent.args", value)
}

// Title create the ECS compliant 'process.parent.title' field.
// Process title. The proctitle, some times the same as process name. Can
// also be different: for example a browser setting its title to the web
// page currently opened.
func (ProcessParent) Title(value string) zapcore.Field {
	return String("process.parent.title", value)
}

// Start create the ECS compliant 'process.parent.start' field.
// The time the process started.
func (ProcessParent) Start(value time.Time) zapcore.Field {
	return Time("process.parent.start", value)
}

// CommandLine create the ECS compliant 'process.parent.command_line' field.
// Full command line that started the process, including the absolute path
// to the executable, and all arguments. Some arguments may be filtered to
// protect sensitive information.
func (ProcessParent) CommandLine(value string) zapcore.Field {
	return String("process.parent.command_line", value)
}

// Executable create the ECS compliant 'process.parent.executable' field.
// Absolute path to the process executable.
func (ProcessParent) Executable(value string) zapcore.Field {
	return String("process.parent.executable", value)
}

// ## process.parent.code_signature fields

// Exists create the ECS compliant 'process.parent.code_signature.exists' field.
// Boolean to capture if a signature is present.
func (ProcessParentCodeSignature) Exists(value bool) zapcore.Field {
	return Bool("process.parent.code_signature.exists", value)
}

// Valid create the ECS compliant 'process.parent.code_signature.valid' field.
// Boolean to capture if the digital signature is verified against the
// binary content. Leave unpopulated if a certificate was unchecked.
func (ProcessParentCodeSignature) Valid(value bool) zapcore.Field {
	return Bool("process.parent.code_signature.valid", value)
}

// SubjectName create the ECS compliant 'process.parent.code_signature.subject_name' field.
// Subject name of the code signer
func (ProcessParentCodeSignature) SubjectName(value string) zapcore.Field {
	return String("process.parent.code_signature.subject_name", value)
}

// Status create the ECS compliant 'process.parent.code_signature.status' field.
// Additional information about the certificate status. This is useful for
// logging cryptographic errors with the certificate validity or trust
// status. Leave unpopulated if the validity or trust of the certificate
// was unchecked.
func (ProcessParentCodeSignature) Status(value string) zapcore.Field {
	return String("process.parent.code_signature.status", value)
}

// Trusted create the ECS compliant 'process.parent.code_signature.trusted' field.
// Stores the trust status of the certificate chain. Validating the trust
// of the certificate chain may be complicated, and this field should only
// be populated by tools that actively check the status.
func (ProcessParentCodeSignature) Trusted(value bool) zapcore.Field {
	return Bool("process.parent.code_signature.trusted", value)
}

// ## process.parent.hash fields

// Sha1 create the ECS compliant 'process.parent.hash.sha1' field.
// SHA1 hash.
func (ProcessParentHash) Sha1(value string) zapcore.Field {
	return String("process.parent.hash.sha1", value)
}

// Sha512 create the ECS compliant 'process.parent.hash.sha512' field.
// SHA512 hash.
func (ProcessParentHash) Sha512(value string) zapcore.Field {
	return String("process.parent.hash.sha512", value)
}

// Sha256 create the ECS compliant 'process.parent.hash.sha256' field.
// SHA256 hash.
func (ProcessParentHash) Sha256(value string) zapcore.Field {
	return String("process.parent.hash.sha256", value)
}

// Md5 create the ECS compliant 'process.parent.hash.md5' field.
// MD5 hash.
func (ProcessParentHash) Md5(value string) zapcore.Field {
	return String("process.parent.hash.md5", value)
}

// ## process.parent.thread fields

// ID create the ECS compliant 'process.parent.thread.id' field.
// Thread ID.
func (ProcessParentThread) ID(value int64) zapcore.Field {
	return Int64("process.parent.thread.id", value)
}

// Name create the ECS compliant 'process.parent.thread.name' field.
// Thread name.
func (ProcessParentThread) Name(value string) zapcore.Field {
	return String("process.parent.thread.name", value)
}

// ## process.pe fields

// Product create the ECS compliant 'process.pe.product' field.
// Internal product name of the file, provided at compile-time.
func (ProcessPe) Product(value string) zapcore.Field {
	return String("process.pe.product", value)
}

// Company create the ECS compliant 'process.pe.company' field.
// Internal company name of the file, provided at compile-time.
func (ProcessPe) Company(value string) zapcore.Field {
	return String("process.pe.company", value)
}

// Description create the ECS compliant 'process.pe.description' field.
// Internal description of the file, provided at compile-time.
func (ProcessPe) Description(value string) zapcore.Field {
	return String("process.pe.description", value)
}

// FileVersion create the ECS compliant 'process.pe.file_version' field.
// Internal version of the file, provided at compile-time.
func (ProcessPe) FileVersion(value string) zapcore.Field {
	return String("process.pe.file_version", value)
}

// OriginalFileName create the ECS compliant 'process.pe.original_file_name' field.
// Internal name of the file, provided at compile-time.
func (ProcessPe) OriginalFileName(value string) zapcore.Field {
	return String("process.pe.original_file_name", value)
}

// ## process.thread fields

// Name create the ECS compliant 'process.thread.name' field.
// Thread name.
func (ProcessThread) Name(value string) zapcore.Field {
	return String("process.thread.name", value)
}

// ID create the ECS compliant 'process.thread.id' field.
// Thread ID.
func (ProcessThread) ID(value int64) zapcore.Field {
	return Int64("process.thread.id", value)
}

// ## registry fields

// Hive create the ECS compliant 'registry.hive' field.
// Abbreviated name for the hive.
func (Registry) Hive(value string) zapcore.Field {
	return String("registry.hive", value)
}

// Path create the ECS compliant 'registry.path' field.
// Full path, including hive, key and value
func (Registry) Path(value string) zapcore.Field {
	return String("registry.path", value)
}

// Key create the ECS compliant 'registry.key' field.
// Hive-relative path of keys.
func (Registry) Key(value string) zapcore.Field {
	return String("registry.key", value)
}

// Value create the ECS compliant 'registry.value' field.
// Name of the value written.
func (Registry) Value(value string) zapcore.Field {
	return String("registry.value", value)
}

// ## registry.data fields

// Type create the ECS compliant 'registry.data.type' field.
// Standard registry type for encoding contents
func (RegistryData) Type(value string) zapcore.Field {
	return String("registry.data.type", value)
}

// Bytes create the ECS compliant 'registry.data.bytes' field.
// Original bytes written with base64 encoding. For Windows registry
// operations, such as SetValueEx and RegQueryValueEx, this corresponds to
// the data pointed by `lp_data`. This is optional but provides better
// recoverability and should be populated for REG_BINARY encoded values.
func (RegistryData) Bytes(value string) zapcore.Field {
	return String("registry.data.bytes", value)
}

// Strings create the ECS compliant 'registry.data.strings' field.
// Content when writing string types. Populated as an array when writing
// string data to the registry. For single string registry types (REG_SZ,
// REG_EXPAND_SZ), this should be an array with one string. For sequences
// of string with REG_MULTI_SZ, this array will be variable length. For
// numeric data, such as REG_DWORD and REG_QWORD, this should be populated
// with the decimal representation (e.g `"1"`).
func (RegistryData) Strings(value string) zapcore.Field {
	return String("registry.data.strings", value)
}

// ## related fields

// User create the ECS compliant 'related.user' field.
// All the user names seen on your event.
func (Related) User(value string) zapcore.Field {
	return String("related.user", value)
}

// IP create the ECS compliant 'related.ip' field.
// All of the IPs seen on your event.
func (Related) IP(value string) zapcore.Field {
	return String("related.ip", value)
}

// Hash create the ECS compliant 'related.hash' field.
// All the hashes seen on your event. Populating this field, then using it
// to search for hashes can help in situations where you're unsure what
// the hash algorithm is (and therefore which key name to search).
func (Related) Hash(value string) zapcore.Field {
	return String("related.hash", value)
}

// ## rule fields

// Reference create the ECS compliant 'rule.reference' field.
// Reference URL to additional information about the rule used to generate
// this event. The URL can point to the vendor's documentation about the
// rule. If that's not available, it can also be a link to a more general
// page describing this type of alert.
func (Rule) Reference(value string) zapcore.Field {
	return String("rule.reference", value)
}

// Name create the ECS compliant 'rule.name' field.
// The name of the rule or signature generating the event.
func (Rule) Name(value string) zapcore.Field {
	return String("rule.name", value)
}

// ID create the ECS compliant 'rule.id' field.
// A rule ID that is unique within the scope of an agent, observer, or
// other entity using the rule for detection of this event.
func (Rule) ID(value string) zapcore.Field {
	return String("rule.id", value)
}

// License create the ECS compliant 'rule.license' field.
// Name of the license under which the rule used to generate this event is
// made available.
func (Rule) License(value string) zapcore.Field {
	return String("rule.license", value)
}

// Description create the ECS compliant 'rule.description' field.
// The description of the rule generating the event.
func (Rule) Description(value string) zapcore.Field {
	return String("rule.description", value)
}

// Version create the ECS compliant 'rule.version' field.
// The version / revision of the rule being used for analysis.
func (Rule) Version(value string) zapcore.Field {
	return String("rule.version", value)
}

// Category create the ECS compliant 'rule.category' field.
// A categorization value keyword used by the entity using the rule for
// detection of this event.
func (Rule) Category(value string) zapcore.Field {
	return String("rule.category", value)
}

// UUID create the ECS compliant 'rule.uuid' field.
// A rule ID that is unique within the scope of a set or group of agents,
// observers, or other entities using the rule for detection of this
// event.
func (Rule) UUID(value string) zapcore.Field {
	return String("rule.uuid", value)
}

// Ruleset create the ECS compliant 'rule.ruleset' field.
// Name of the ruleset, policy, group, or parent category in which the
// rule used to generate this event is a member.
func (Rule) Ruleset(value string) zapcore.Field {
	return String("rule.ruleset", value)
}

// Author create the ECS compliant 'rule.author' field.
// Name, organization, or pseudonym of the author or authors who created
// the rule used to generate this event.
func (Rule) Author(value string) zapcore.Field {
	return String("rule.author", value)
}

// ## server fields

// Bytes create the ECS compliant 'server.bytes' field.
// Bytes sent from the server to the client.
func (Server) Bytes(value int64) zapcore.Field {
	return Int64("server.bytes", value)
}

// RegisteredDomain create the ECS compliant 'server.registered_domain' field.
// The highest registered server domain, stripped of the subdomain. For
// example, the registered domain for "foo.google.com" is "google.com".
// This value can be determined precisely with a list like the public
// suffix list (http://publicsuffix.org). Trying to approximate this by
// simply taking the last two labels will not work well for TLDs such as
// "co.uk".
func (Server) RegisteredDomain(value string) zapcore.Field {
	return String("server.registered_domain", value)
}

// MAC create the ECS compliant 'server.mac' field.
// MAC address of the server.
func (Server) MAC(value string) zapcore.Field {
	return String("server.mac", value)
}

// IP create the ECS compliant 'server.ip' field.
// IP address of the server. Can be one or multiple IPv4 or IPv6
// addresses.
func (Server) IP(value string) zapcore.Field {
	return String("server.ip", value)
}

// Domain create the ECS compliant 'server.domain' field.
// Server domain.
func (Server) Domain(value string) zapcore.Field {
	return String("server.domain", value)
}

// Address create the ECS compliant 'server.address' field.
// Some event server addresses are defined ambiguously. The event will
// sometimes list an IP, a domain or a unix socket.  You should always
// store the raw address in the `.address` field. Then it should be
// duplicated to `.ip` or `.domain`, depending on which one it is.
func (Server) Address(value string) zapcore.Field {
	return String("server.address", value)
}

// Packets create the ECS compliant 'server.packets' field.
// Packets sent from the server to the client.
func (Server) Packets(value int64) zapcore.Field {
	return Int64("server.packets", value)
}

// Port create the ECS compliant 'server.port' field.
// Port of the server.
func (Server) Port(value int64) zapcore.Field {
	return Int64("server.port", value)
}

// TopLevelDomain create the ECS compliant 'server.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (Server) TopLevelDomain(value string) zapcore.Field {
	return String("server.top_level_domain", value)
}

// ## server.as fields

// Number create the ECS compliant 'server.as.number' field.
// Unique number allocated to the autonomous system. The autonomous system
// number (ASN) uniquely identifies each network on the Internet.
func (ServerAs) Number(value int64) zapcore.Field {
	return Int64("server.as.number", value)
}

// ## server.as.organization fields

// Name create the ECS compliant 'server.as.organization.name' field.
// Organization name.
func (ServerAsOrganization) Name(value string) zapcore.Field {
	return String("server.as.organization.name", value)
}

// ## server.geo fields

// RegionIsoCode create the ECS compliant 'server.geo.region_iso_code' field.
// Region ISO code.
func (ServerGeo) RegionIsoCode(value string) zapcore.Field {
	return String("server.geo.region_iso_code", value)
}

// ContinentName create the ECS compliant 'server.geo.continent_name' field.
// Name of the continent.
func (ServerGeo) ContinentName(value string) zapcore.Field {
	return String("server.geo.continent_name", value)
}

// CountryName create the ECS compliant 'server.geo.country_name' field.
// Country name.
func (ServerGeo) CountryName(value string) zapcore.Field {
	return String("server.geo.country_name", value)
}

// Name create the ECS compliant 'server.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (ServerGeo) Name(value string) zapcore.Field {
	return String("server.geo.name", value)
}

// CityName create the ECS compliant 'server.geo.city_name' field.
// City name.
func (ServerGeo) CityName(value string) zapcore.Field {
	return String("server.geo.city_name", value)
}

// RegionName create the ECS compliant 'server.geo.region_name' field.
// Region name.
func (ServerGeo) RegionName(value string) zapcore.Field {
	return String("server.geo.region_name", value)
}

// Location create the ECS compliant 'server.geo.location' field.
// Longitude and latitude.
func (ServerGeo) Location(value string) zapcore.Field {
	return String("server.geo.location", value)
}

// CountryIsoCode create the ECS compliant 'server.geo.country_iso_code' field.
// Country ISO code.
func (ServerGeo) CountryIsoCode(value string) zapcore.Field {
	return String("server.geo.country_iso_code", value)
}

// ## server.nat fields

// IP create the ECS compliant 'server.nat.ip' field.
// Translated ip of destination based NAT sessions (e.g. internet to
// private DMZ) Typically used with load balancers, firewalls, or routers.
func (ServerNat) IP(value string) zapcore.Field {
	return String("server.nat.ip", value)
}

// Port create the ECS compliant 'server.nat.port' field.
// Translated port of destination based NAT sessions (e.g. internet to
// private DMZ) Typically used with load balancers, firewalls, or routers.
func (ServerNat) Port(value int64) zapcore.Field {
	return Int64("server.nat.port", value)
}

// ## server.user fields

// Email create the ECS compliant 'server.user.email' field.
// User email address.
func (ServerUser) Email(value string) zapcore.Field {
	return String("server.user.email", value)
}

// Name create the ECS compliant 'server.user.name' field.
// Short name or login of the user.
func (ServerUser) Name(value string) zapcore.Field {
	return String("server.user.name", value)
}

// Domain create the ECS compliant 'server.user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (ServerUser) Domain(value string) zapcore.Field {
	return String("server.user.domain", value)
}

// FullName create the ECS compliant 'server.user.full_name' field.
// User's full name, if available.
func (ServerUser) FullName(value string) zapcore.Field {
	return String("server.user.full_name", value)
}

// ID create the ECS compliant 'server.user.id' field.
// Unique identifiers of the user.
func (ServerUser) ID(value string) zapcore.Field {
	return String("server.user.id", value)
}

// Hash create the ECS compliant 'server.user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (ServerUser) Hash(value string) zapcore.Field {
	return String("server.user.hash", value)
}

// ## server.user.group fields

// Name create the ECS compliant 'server.user.group.name' field.
// Name of the group.
func (ServerUserGroup) Name(value string) zapcore.Field {
	return String("server.user.group.name", value)
}

// Domain create the ECS compliant 'server.user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (ServerUserGroup) Domain(value string) zapcore.Field {
	return String("server.user.group.domain", value)
}

// ID create the ECS compliant 'server.user.group.id' field.
// Unique identifier for the group on the system/platform.
func (ServerUserGroup) ID(value string) zapcore.Field {
	return String("server.user.group.id", value)
}

// ## service fields

// Version create the ECS compliant 'service.version' field.
// Version of the service the data was collected from. This allows to look
// at a data set only for a specific version of a service.
func (Service) Version(value string) zapcore.Field {
	return String("service.version", value)
}

// Name create the ECS compliant 'service.name' field.
// Name of the service data is collected from. The name of the service is
// normally user given. This allows for distributed services that run on
// multiple hosts to correlate the related instances based on the name. In
// the case of Elasticsearch the `service.name` could contain the cluster
// name. For Beats the `service.name` is by default a copy of the
// `service.type` field if no name is specified.
func (Service) Name(value string) zapcore.Field {
	return String("service.name", value)
}

// ID create the ECS compliant 'service.id' field.
// Unique identifier of the running service. If the service is comprised
// of many nodes, the `service.id` should be the same for all nodes. This
// id should uniquely identify the service. This makes it possible to
// correlate logs and metrics for one specific service, no matter which
// particular node emitted the event. Note that if you need to see the
// events from one specific host of the service, you should filter on that
// `host.name` or `host.id` instead.
func (Service) ID(value string) zapcore.Field {
	return String("service.id", value)
}

// EphemeralID create the ECS compliant 'service.ephemeral_id' field.
// Ephemeral identifier of this service (if one exists). This id normally
// changes across restarts, but `service.id` does not.
func (Service) EphemeralID(value string) zapcore.Field {
	return String("service.ephemeral_id", value)
}

// Type create the ECS compliant 'service.type' field.
// The type of the service data is collected from. The type can be used to
// group and correlate logs and metrics from one service type. Example: If
// logs or metrics are collected from Elasticsearch, `service.type` would
// be `elasticsearch`.
func (Service) Type(value string) zapcore.Field {
	return String("service.type", value)
}

// State create the ECS compliant 'service.state' field.
// Current state of the service.
func (Service) State(value string) zapcore.Field {
	return String("service.state", value)
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
func (ServiceNode) Name(value string) zapcore.Field {
	return String("service.node.name", value)
}

// ## source fields

// IP create the ECS compliant 'source.ip' field.
// IP address of the source. Can be one or multiple IPv4 or IPv6
// addresses.
func (Source) IP(value string) zapcore.Field {
	return String("source.ip", value)
}

// Domain create the ECS compliant 'source.domain' field.
// Source domain.
func (Source) Domain(value string) zapcore.Field {
	return String("source.domain", value)
}

// Port create the ECS compliant 'source.port' field.
// Port of the source.
func (Source) Port(value int64) zapcore.Field {
	return Int64("source.port", value)
}

// Packets create the ECS compliant 'source.packets' field.
// Packets sent from the source to the destination.
func (Source) Packets(value int64) zapcore.Field {
	return Int64("source.packets", value)
}

// Bytes create the ECS compliant 'source.bytes' field.
// Bytes sent from the source to the destination.
func (Source) Bytes(value int64) zapcore.Field {
	return Int64("source.bytes", value)
}

// Address create the ECS compliant 'source.address' field.
// Some event source addresses are defined ambiguously. The event will
// sometimes list an IP, a domain or a unix socket.  You should always
// store the raw address in the `.address` field. Then it should be
// duplicated to `.ip` or `.domain`, depending on which one it is.
func (Source) Address(value string) zapcore.Field {
	return String("source.address", value)
}

// RegisteredDomain create the ECS compliant 'source.registered_domain' field.
// The highest registered source domain, stripped of the subdomain. For
// example, the registered domain for "foo.google.com" is "google.com".
// This value can be determined precisely with a list like the public
// suffix list (http://publicsuffix.org). Trying to approximate this by
// simply taking the last two labels will not work well for TLDs such as
// "co.uk".
func (Source) RegisteredDomain(value string) zapcore.Field {
	return String("source.registered_domain", value)
}

// TopLevelDomain create the ECS compliant 'source.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (Source) TopLevelDomain(value string) zapcore.Field {
	return String("source.top_level_domain", value)
}

// MAC create the ECS compliant 'source.mac' field.
// MAC address of the source.
func (Source) MAC(value string) zapcore.Field {
	return String("source.mac", value)
}

// ## source.as fields

// Number create the ECS compliant 'source.as.number' field.
// Unique number allocated to the autonomous system. The autonomous system
// number (ASN) uniquely identifies each network on the Internet.
func (SourceAs) Number(value int64) zapcore.Field {
	return Int64("source.as.number", value)
}

// ## source.as.organization fields

// Name create the ECS compliant 'source.as.organization.name' field.
// Organization name.
func (SourceAsOrganization) Name(value string) zapcore.Field {
	return String("source.as.organization.name", value)
}

// ## source.geo fields

// CountryName create the ECS compliant 'source.geo.country_name' field.
// Country name.
func (SourceGeo) CountryName(value string) zapcore.Field {
	return String("source.geo.country_name", value)
}

// CityName create the ECS compliant 'source.geo.city_name' field.
// City name.
func (SourceGeo) CityName(value string) zapcore.Field {
	return String("source.geo.city_name", value)
}

// CountryIsoCode create the ECS compliant 'source.geo.country_iso_code' field.
// Country ISO code.
func (SourceGeo) CountryIsoCode(value string) zapcore.Field {
	return String("source.geo.country_iso_code", value)
}

// Name create the ECS compliant 'source.geo.name' field.
// User-defined description of a location, at the level of granularity
// they care about. Could be the name of their data centers, the floor
// number, if this describes a local physical entity, city names. Not
// typically used in automated geolocation.
func (SourceGeo) Name(value string) zapcore.Field {
	return String("source.geo.name", value)
}

// RegionIsoCode create the ECS compliant 'source.geo.region_iso_code' field.
// Region ISO code.
func (SourceGeo) RegionIsoCode(value string) zapcore.Field {
	return String("source.geo.region_iso_code", value)
}

// ContinentName create the ECS compliant 'source.geo.continent_name' field.
// Name of the continent.
func (SourceGeo) ContinentName(value string) zapcore.Field {
	return String("source.geo.continent_name", value)
}

// Location create the ECS compliant 'source.geo.location' field.
// Longitude and latitude.
func (SourceGeo) Location(value string) zapcore.Field {
	return String("source.geo.location", value)
}

// RegionName create the ECS compliant 'source.geo.region_name' field.
// Region name.
func (SourceGeo) RegionName(value string) zapcore.Field {
	return String("source.geo.region_name", value)
}

// ## source.nat fields

// IP create the ECS compliant 'source.nat.ip' field.
// Translated ip of source based NAT sessions (e.g. internal client to
// internet) Typically connections traversing load balancers, firewalls,
// or routers.
func (SourceNat) IP(value string) zapcore.Field {
	return String("source.nat.ip", value)
}

// Port create the ECS compliant 'source.nat.port' field.
// Translated port of source based NAT sessions. (e.g. internal client to
// internet) Typically used with load balancers, firewalls, or routers.
func (SourceNat) Port(value int64) zapcore.Field {
	return Int64("source.nat.port", value)
}

// ## source.user fields

// Email create the ECS compliant 'source.user.email' field.
// User email address.
func (SourceUser) Email(value string) zapcore.Field {
	return String("source.user.email", value)
}

// Name create the ECS compliant 'source.user.name' field.
// Short name or login of the user.
func (SourceUser) Name(value string) zapcore.Field {
	return String("source.user.name", value)
}

// ID create the ECS compliant 'source.user.id' field.
// Unique identifiers of the user.
func (SourceUser) ID(value string) zapcore.Field {
	return String("source.user.id", value)
}

// Domain create the ECS compliant 'source.user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (SourceUser) Domain(value string) zapcore.Field {
	return String("source.user.domain", value)
}

// FullName create the ECS compliant 'source.user.full_name' field.
// User's full name, if available.
func (SourceUser) FullName(value string) zapcore.Field {
	return String("source.user.full_name", value)
}

// Hash create the ECS compliant 'source.user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (SourceUser) Hash(value string) zapcore.Field {
	return String("source.user.hash", value)
}

// ## source.user.group fields

// ID create the ECS compliant 'source.user.group.id' field.
// Unique identifier for the group on the system/platform.
func (SourceUserGroup) ID(value string) zapcore.Field {
	return String("source.user.group.id", value)
}

// Domain create the ECS compliant 'source.user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (SourceUserGroup) Domain(value string) zapcore.Field {
	return String("source.user.group.domain", value)
}

// Name create the ECS compliant 'source.user.group.name' field.
// Name of the group.
func (SourceUserGroup) Name(value string) zapcore.Field {
	return String("source.user.group.name", value)
}

// ## threat fields

// Framework create the ECS compliant 'threat.framework' field.
// Name of the threat framework used to further categorize and classify
// the tactic and technique of the reported threat. Framework
// classification can be provided by detecting systems, evaluated at
// ingest time, or retrospectively tagged to events.
func (Threat) Framework(value string) zapcore.Field {
	return String("threat.framework", value)
}

// ## threat.tactic fields

// ID create the ECS compliant 'threat.tactic.id' field.
// The id of tactic used by this threat. You can use the Mitre ATT&CK
// Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/tactics/TA0040/ )
func (ThreatTactic) ID(value string) zapcore.Field {
	return String("threat.tactic.id", value)
}

// Name create the ECS compliant 'threat.tactic.name' field.
// Name of the type of tactic used by this threat. You can use the Mitre
// ATT&CK Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/tactics/TA0040/ )
func (ThreatTactic) Name(value string) zapcore.Field {
	return String("threat.tactic.name", value)
}

// Reference create the ECS compliant 'threat.tactic.reference' field.
// The reference url of tactic used by this threat. You can use the Mitre
// ATT&CK Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/tactics/TA0040/ )
func (ThreatTactic) Reference(value string) zapcore.Field {
	return String("threat.tactic.reference", value)
}

// ## threat.technique fields

// Reference create the ECS compliant 'threat.technique.reference' field.
// The reference url of technique used by this tactic. You can use the
// Mitre ATT&CK Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/techniques/T1499/ )
func (ThreatTechnique) Reference(value string) zapcore.Field {
	return String("threat.technique.reference", value)
}

// ID create the ECS compliant 'threat.technique.id' field.
// The id of technique used by this tactic. You can use the Mitre ATT&CK
// Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/techniques/T1499/ )
func (ThreatTechnique) ID(value string) zapcore.Field {
	return String("threat.technique.id", value)
}

// Name create the ECS compliant 'threat.technique.name' field.
// The name of technique used by this tactic. You can use the Mitre ATT&CK
// Matrix Tactic categorization, for example. (ex.
// https://attack.mitre.org/techniques/T1499/ )
func (ThreatTechnique) Name(value string) zapcore.Field {
	return String("threat.technique.name", value)
}

// ## tls fields

// VersionProtocol create the ECS compliant 'tls.version_protocol' field.
// Normalized lowercase protocol name parsed from original string.
func (TLS) VersionProtocol(value string) zapcore.Field {
	return String("tls.version_protocol", value)
}

// Version create the ECS compliant 'tls.version' field.
// Numeric part of the version parsed from the original string.
func (TLS) Version(value string) zapcore.Field {
	return String("tls.version", value)
}

// Cipher create the ECS compliant 'tls.cipher' field.
// String indicating the cipher used during the current connection.
func (TLS) Cipher(value string) zapcore.Field {
	return String("tls.cipher", value)
}

// Established create the ECS compliant 'tls.established' field.
// Boolean flag indicating if the TLS negotiation was successful and
// transitioned to an encrypted tunnel.
func (TLS) Established(value bool) zapcore.Field {
	return Bool("tls.established", value)
}

// Resumed create the ECS compliant 'tls.resumed' field.
// Boolean flag indicating if this TLS connection was resumed from an
// existing TLS negotiation.
func (TLS) Resumed(value bool) zapcore.Field {
	return Bool("tls.resumed", value)
}

// NextProtocol create the ECS compliant 'tls.next_protocol' field.
// String indicating the protocol being tunneled. Per the values in the
// IANA registry
// (https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids),
// this string should be lower case.
func (TLS) NextProtocol(value string) zapcore.Field {
	return String("tls.next_protocol", value)
}

// Curve create the ECS compliant 'tls.curve' field.
// String indicating the curve used for the given cipher, when applicable.
func (TLS) Curve(value string) zapcore.Field {
	return String("tls.curve", value)
}

// ## tls.client fields

// SupportedCiphers create the ECS compliant 'tls.client.supported_ciphers' field.
// Array of ciphers offered by the client during the client hello.
func (TLSClient) SupportedCiphers(value string) zapcore.Field {
	return String("tls.client.supported_ciphers", value)
}

// Certificate create the ECS compliant 'tls.client.certificate' field.
// PEM-encoded stand-alone certificate offered by the client. This is
// usually mutually-exclusive of `client.certificate_chain` since this
// value also exists in that list.
func (TLSClient) Certificate(value string) zapcore.Field {
	return String("tls.client.certificate", value)
}

// NotAfter create the ECS compliant 'tls.client.not_after' field.
// Date/Time indicating when client certificate is no longer considered
// valid.
func (TLSClient) NotAfter(value time.Time) zapcore.Field {
	return Time("tls.client.not_after", value)
}

// NotBefore create the ECS compliant 'tls.client.not_before' field.
// Date/Time indicating when client certificate is first considered valid.
func (TLSClient) NotBefore(value time.Time) zapcore.Field {
	return Time("tls.client.not_before", value)
}

// Ja3 create the ECS compliant 'tls.client.ja3' field.
// A hash that identifies clients based on how they perform an SSL/TLS
// handshake.
func (TLSClient) Ja3(value string) zapcore.Field {
	return String("tls.client.ja3", value)
}

// Issuer create the ECS compliant 'tls.client.issuer' field.
// Distinguished name of subject of the issuer of the x.509 certificate
// presented by the client.
func (TLSClient) Issuer(value string) zapcore.Field {
	return String("tls.client.issuer", value)
}

// ServerName create the ECS compliant 'tls.client.server_name' field.
// Also called an SNI, this tells the server which hostname to which the
// client is attempting to connect. When this value is available, it
// should get copied to `destination.domain`.
func (TLSClient) ServerName(value string) zapcore.Field {
	return String("tls.client.server_name", value)
}

// CertificateChain create the ECS compliant 'tls.client.certificate_chain' field.
// Array of PEM-encoded certificates that make up the certificate chain
// offered by the client. This is usually mutually-exclusive of
// `client.certificate` since that value should be the first certificate
// in the chain.
func (TLSClient) CertificateChain(value string) zapcore.Field {
	return String("tls.client.certificate_chain", value)
}

// Subject create the ECS compliant 'tls.client.subject' field.
// Distinguished name of subject of the x.509 certificate presented by the
// client.
func (TLSClient) Subject(value string) zapcore.Field {
	return String("tls.client.subject", value)
}

// ## tls.client.hash fields

// Sha1 create the ECS compliant 'tls.client.hash.sha1' field.
// Certificate fingerprint using the SHA1 digest of DER-encoded version of
// certificate offered by the client. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (TLSClientHash) Sha1(value string) zapcore.Field {
	return String("tls.client.hash.sha1", value)
}

// Md5 create the ECS compliant 'tls.client.hash.md5' field.
// Certificate fingerprint using the MD5 digest of DER-encoded version of
// certificate offered by the client. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (TLSClientHash) Md5(value string) zapcore.Field {
	return String("tls.client.hash.md5", value)
}

// Sha256 create the ECS compliant 'tls.client.hash.sha256' field.
// Certificate fingerprint using the SHA256 digest of DER-encoded version
// of certificate offered by the client. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (TLSClientHash) Sha256(value string) zapcore.Field {
	return String("tls.client.hash.sha256", value)
}

// ## tls.server fields

// Certificate create the ECS compliant 'tls.server.certificate' field.
// PEM-encoded stand-alone certificate offered by the server. This is
// usually mutually-exclusive of `server.certificate_chain` since this
// value also exists in that list.
func (TLSServer) Certificate(value string) zapcore.Field {
	return String("tls.server.certificate", value)
}

// NotAfter create the ECS compliant 'tls.server.not_after' field.
// Timestamp indicating when server certificate is no longer considered
// valid.
func (TLSServer) NotAfter(value time.Time) zapcore.Field {
	return Time("tls.server.not_after", value)
}

// Ja3s create the ECS compliant 'tls.server.ja3s' field.
// A hash that identifies servers based on how they perform an SSL/TLS
// handshake.
func (TLSServer) Ja3s(value string) zapcore.Field {
	return String("tls.server.ja3s", value)
}

// CertificateChain create the ECS compliant 'tls.server.certificate_chain' field.
// Array of PEM-encoded certificates that make up the certificate chain
// offered by the server. This is usually mutually-exclusive of
// `server.certificate` since that value should be the first certificate
// in the chain.
func (TLSServer) CertificateChain(value string) zapcore.Field {
	return String("tls.server.certificate_chain", value)
}

// NotBefore create the ECS compliant 'tls.server.not_before' field.
// Timestamp indicating when server certificate is first considered valid.
func (TLSServer) NotBefore(value time.Time) zapcore.Field {
	return Time("tls.server.not_before", value)
}

// Subject create the ECS compliant 'tls.server.subject' field.
// Subject of the x.509 certificate presented by the server.
func (TLSServer) Subject(value string) zapcore.Field {
	return String("tls.server.subject", value)
}

// Issuer create the ECS compliant 'tls.server.issuer' field.
// Subject of the issuer of the x.509 certificate presented by the server.
func (TLSServer) Issuer(value string) zapcore.Field {
	return String("tls.server.issuer", value)
}

// ## tls.server.hash fields

// Md5 create the ECS compliant 'tls.server.hash.md5' field.
// Certificate fingerprint using the MD5 digest of DER-encoded version of
// certificate offered by the server. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (TLSServerHash) Md5(value string) zapcore.Field {
	return String("tls.server.hash.md5", value)
}

// Sha256 create the ECS compliant 'tls.server.hash.sha256' field.
// Certificate fingerprint using the SHA256 digest of DER-encoded version
// of certificate offered by the server. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (TLSServerHash) Sha256(value string) zapcore.Field {
	return String("tls.server.hash.sha256", value)
}

// Sha1 create the ECS compliant 'tls.server.hash.sha1' field.
// Certificate fingerprint using the SHA1 digest of DER-encoded version of
// certificate offered by the server. For consistency with other hash
// values, this value should be formatted as an uppercase hash.
func (TLSServerHash) Sha1(value string) zapcore.Field {
	return String("tls.server.hash.sha1", value)
}

// ## trace fields

// ID create the ECS compliant 'trace.id' field.
// Unique identifier of the trace. A trace groups multiple events like
// transactions that belong together. For example, a user request handled
// by multiple inter-connected services.
func (Trace) ID(value string) zapcore.Field {
	return String("trace.id", value)
}

// ## transaction fields

// ID create the ECS compliant 'transaction.id' field.
// Unique identifier of the transaction. A transaction is the highest
// level of work measured within a service, such as a request to a server.
func (Transaction) ID(value string) zapcore.Field {
	return String("transaction.id", value)
}

// ## url fields

// Path create the ECS compliant 'url.path' field.
// Path of the request, such as "/search".
func (URL) Path(value string) zapcore.Field {
	return String("url.path", value)
}

// Port create the ECS compliant 'url.port' field.
// Port of the request, such as 443.
func (URL) Port(value int64) zapcore.Field {
	return Int64("url.port", value)
}

// Scheme create the ECS compliant 'url.scheme' field.
// Scheme of the request, such as "https". Note: The `:` is not part of
// the scheme.
func (URL) Scheme(value string) zapcore.Field {
	return String("url.scheme", value)
}

// Fragment create the ECS compliant 'url.fragment' field.
// Portion of the url after the `#`, such as "top". The `#` is not part of
// the fragment.
func (URL) Fragment(value string) zapcore.Field {
	return String("url.fragment", value)
}

// Domain create the ECS compliant 'url.domain' field.
// Domain of the url, such as "www.elastic.co". In some cases a URL may
// refer to an IP and/or port directly, without a domain name. In this
// case, the IP address would go to the `domain` field.
func (URL) Domain(value string) zapcore.Field {
	return String("url.domain", value)
}

// TopLevelDomain create the ECS compliant 'url.top_level_domain' field.
// The effective top level domain (eTLD), also known as the domain suffix,
// is the last part of the domain name. For example, the top level domain
// for google.com is "com". This value can be determined precisely with a
// list like the public suffix list (http://publicsuffix.org). Trying to
// approximate this by simply taking the last label will not work well for
// effective TLDs such as "co.uk".
func (URL) TopLevelDomain(value string) zapcore.Field {
	return String("url.top_level_domain", value)
}

// Password create the ECS compliant 'url.password' field.
// Password of the request.
func (URL) Password(value string) zapcore.Field {
	return String("url.password", value)
}

// Extension create the ECS compliant 'url.extension' field.
// The field contains the file extension from the original request url.
// The file extension is only set if it exists, as not every url has a
// file extension. The leading period must not be included. For example,
// the value must be "png", not ".png".
func (URL) Extension(value string) zapcore.Field {
	return String("url.extension", value)
}

// Full create the ECS compliant 'url.full' field.
// If full URLs are important to your use case, they should be stored in
// `url.full`, whether this field is reconstructed or present in the event
// source.
func (URL) Full(value string) zapcore.Field {
	return String("url.full", value)
}

// RegisteredDomain create the ECS compliant 'url.registered_domain' field.
// The highest registered url domain, stripped of the subdomain. For
// example, the registered domain for "foo.google.com" is "google.com".
// This value can be determined precisely with a list like the public
// suffix list (http://publicsuffix.org). Trying to approximate this by
// simply taking the last two labels will not work well for TLDs such as
// "co.uk".
func (URL) RegisteredDomain(value string) zapcore.Field {
	return String("url.registered_domain", value)
}

// Original create the ECS compliant 'url.original' field.
// Unmodified original url as seen in the event source. Note that in
// network monitoring, the observed URL may be a full URL, whereas in
// access logs, the URL is often just represented as a path. This field is
// meant to represent the URL as it was observed, complete or not.
func (URL) Original(value string) zapcore.Field {
	return String("url.original", value)
}

// Username create the ECS compliant 'url.username' field.
// Username of the request.
func (URL) Username(value string) zapcore.Field {
	return String("url.username", value)
}

// Query create the ECS compliant 'url.query' field.
// The query field describes the query string of the request, such as
// "q=elasticsearch". The `?` is excluded from the query string. If a URL
// contains no `?`, there is no query field. If there is a `?` but no
// query, the query field exists with an empty string. The `exists` query
// can be used to differentiate between the two cases.
func (URL) Query(value string) zapcore.Field {
	return String("url.query", value)
}

// ## user fields

// FullName create the ECS compliant 'user.full_name' field.
// User's full name, if available.
func (User) FullName(value string) zapcore.Field {
	return String("user.full_name", value)
}

// Name create the ECS compliant 'user.name' field.
// Short name or login of the user.
func (User) Name(value string) zapcore.Field {
	return String("user.name", value)
}

// ID create the ECS compliant 'user.id' field.
// Unique identifiers of the user.
func (User) ID(value string) zapcore.Field {
	return String("user.id", value)
}

// Hash create the ECS compliant 'user.hash' field.
// Unique user hash to correlate information for a user in anonymized
// form. Useful if `user.id` or `user.name` contain confidential
// information and cannot be used.
func (User) Hash(value string) zapcore.Field {
	return String("user.hash", value)
}

// Email create the ECS compliant 'user.email' field.
// User email address.
func (User) Email(value string) zapcore.Field {
	return String("user.email", value)
}

// Domain create the ECS compliant 'user.domain' field.
// Name of the directory the user is a member of. For example, an LDAP or
// Active Directory domain name.
func (User) Domain(value string) zapcore.Field {
	return String("user.domain", value)
}

// ## user.group fields

// Domain create the ECS compliant 'user.group.domain' field.
// Name of the directory the group is a member of. For example, an LDAP or
// Active Directory domain name.
func (UserGroup) Domain(value string) zapcore.Field {
	return String("user.group.domain", value)
}

// Name create the ECS compliant 'user.group.name' field.
// Name of the group.
func (UserGroup) Name(value string) zapcore.Field {
	return String("user.group.name", value)
}

// ID create the ECS compliant 'user.group.id' field.
// Unique identifier for the group on the system/platform.
func (UserGroup) ID(value string) zapcore.Field {
	return String("user.group.id", value)
}

// ## user_agent fields

// Version create the ECS compliant 'user_agent.version' field.
// Version of the user agent.
func (UserAgent) Version(value string) zapcore.Field {
	return String("user_agent.version", value)
}

// Original create the ECS compliant 'user_agent.original' field.
// Unparsed user_agent string.
func (UserAgent) Original(value string) zapcore.Field {
	return String("user_agent.original", value)
}

// Name create the ECS compliant 'user_agent.name' field.
// Name of the user agent.
func (UserAgent) Name(value string) zapcore.Field {
	return String("user_agent.name", value)
}

// ## user_agent.device fields

// Name create the ECS compliant 'user_agent.device.name' field.
// Name of the device.
func (UserAgentDevice) Name(value string) zapcore.Field {
	return String("user_agent.device.name", value)
}

// ## user_agent.os fields

// Full create the ECS compliant 'user_agent.os.full' field.
// Operating system name, including the version or code name.
func (UserAgentOS) Full(value string) zapcore.Field {
	return String("user_agent.os.full", value)
}

// Platform create the ECS compliant 'user_agent.os.platform' field.
// Operating system platform (such centos, ubuntu, windows).
func (UserAgentOS) Platform(value string) zapcore.Field {
	return String("user_agent.os.platform", value)
}

// Name create the ECS compliant 'user_agent.os.name' field.
// Operating system name, without the version.
func (UserAgentOS) Name(value string) zapcore.Field {
	return String("user_agent.os.name", value)
}

// Kernel create the ECS compliant 'user_agent.os.kernel' field.
// Operating system kernel version as a raw string.
func (UserAgentOS) Kernel(value string) zapcore.Field {
	return String("user_agent.os.kernel", value)
}

// Version create the ECS compliant 'user_agent.os.version' field.
// Operating system version as a raw string.
func (UserAgentOS) Version(value string) zapcore.Field {
	return String("user_agent.os.version", value)
}

// Family create the ECS compliant 'user_agent.os.family' field.
// OS family (such as redhat, debian, freebsd, windows).
func (UserAgentOS) Family(value string) zapcore.Field {
	return String("user_agent.os.family", value)
}

// ## vlan fields

// ID create the ECS compliant 'vlan.id' field.
// VLAN ID as reported by the observer.
func (Vlan) ID(value string) zapcore.Field {
	return String("vlan.id", value)
}

// Name create the ECS compliant 'vlan.name' field.
// Optional VLAN name as reported by the observer.
func (Vlan) Name(value string) zapcore.Field {
	return String("vlan.name", value)
}

// ## vulnerability fields

// ReportID create the ECS compliant 'vulnerability.report_id' field.
// The report or scan identification number.
func (Vulnerability) ReportID(value string) zapcore.Field {
	return String("vulnerability.report_id", value)
}

// Reference create the ECS compliant 'vulnerability.reference' field.
// A resource that provides additional information, context, and
// mitigations for the identified vulnerability.
func (Vulnerability) Reference(value string) zapcore.Field {
	return String("vulnerability.reference", value)
}

// Category create the ECS compliant 'vulnerability.category' field.
// The type of system or architecture that the vulnerability affects.
// These may be platform-specific (for example, Debian or SUSE) or general
// (for example, Database or Firewall). For example
// (https://qualysguard.qualys.com/qwebhelp/fo_portal/knowledgebase/vulnerability_categories.htm[Qualys
// vulnerability categories]) This field must be an array.
func (Vulnerability) Category(value string) zapcore.Field {
	return String("vulnerability.category", value)
}

// Description create the ECS compliant 'vulnerability.description' field.
// The description of the vulnerability that provides additional context
// of the vulnerability. For example
// (https://cve.mitre.org/about/faqs.html#cve_entry_descriptions_created[Common
// Vulnerabilities and Exposure CVE description])
func (Vulnerability) Description(value string) zapcore.Field {
	return String("vulnerability.description", value)
}

// Severity create the ECS compliant 'vulnerability.severity' field.
// The severity of the vulnerability can help with metrics and internal
// prioritization regarding remediation. For example
// (https://nvd.nist.gov/vuln-metrics/cvss)
func (Vulnerability) Severity(value string) zapcore.Field {
	return String("vulnerability.severity", value)
}

// Enumeration create the ECS compliant 'vulnerability.enumeration' field.
// The type of identifier used for this vulnerability. For example
// (https://cve.mitre.org/about/)
func (Vulnerability) Enumeration(value string) zapcore.Field {
	return String("vulnerability.enumeration", value)
}

// ID create the ECS compliant 'vulnerability.id' field.
// The identification (ID) is the number portion of a vulnerability entry.
// It includes a unique identification number for the vulnerability. For
// example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common
// Vulnerabilities and Exposure CVE ID]
func (Vulnerability) ID(value string) zapcore.Field {
	return String("vulnerability.id", value)
}

// Classification create the ECS compliant 'vulnerability.classification' field.
// The classification of the vulnerability scoring system. For example
// (https://www.first.org/cvss/)
func (Vulnerability) Classification(value string) zapcore.Field {
	return String("vulnerability.classification", value)
}

// ## vulnerability.scanner fields

// Vendor create the ECS compliant 'vulnerability.scanner.vendor' field.
// The name of the vulnerability scanner vendor.
func (VulnerabilityScanner) Vendor(value string) zapcore.Field {
	return String("vulnerability.scanner.vendor", value)
}

// ## vulnerability.score fields

// Version create the ECS compliant 'vulnerability.score.version' field.
// The National Vulnerability Database (NVD) provides qualitative severity
// rankings of "Low", "Medium", and "High" for CVSS v2.0 base score ranges
// in addition to the severity ratings for CVSS v3.0 as they are defined
// in the CVSS v3.0 specification. CVSS is owned and managed by FIRST.Org,
// Inc. (FIRST), a US-based non-profit organization, whose mission is to
// help computer security incident response teams across the world. For
// example (https://nvd.nist.gov/vuln-metrics/cvss)
func (VulnerabilityScore) Version(value string) zapcore.Field {
	return String("vulnerability.score.version", value)
}

// Environmental create the ECS compliant 'vulnerability.score.environmental' field.
// Scores can range from 0.0 to 10.0, with 10.0 being the most severe.
// Environmental scores cover an assessment for any modified Base metrics,
// confidentiality, integrity, and availability requirements. For example
// (https://www.first.org/cvss/specification-document)
func (VulnerabilityScore) Environmental(value float64) zapcore.Field {
	return Float64("vulnerability.score.environmental", value)
}

// Base create the ECS compliant 'vulnerability.score.base' field.
// Scores can range from 0.0 to 10.0, with 10.0 being the most severe.
// Base scores cover an assessment for exploitability metrics (attack
// vector, complexity, privileges, and user interaction), impact metrics
// (confidentiality, integrity, and availability), and scope. For example
// (https://www.first.org/cvss/specification-document)
func (VulnerabilityScore) Base(value float64) zapcore.Field {
	return Float64("vulnerability.score.base", value)
}

// Temporal create the ECS compliant 'vulnerability.score.temporal' field.
// Scores can range from 0.0 to 10.0, with 10.0 being the most severe.
// Temporal scores cover an assessment for code maturity, remediation
// level, and confidence. For example
// (https://www.first.org/cvss/specification-document)
func (VulnerabilityScore) Temporal(value float64) zapcore.Field {
	return Float64("vulnerability.score.temporal", value)
}

func Time(key string, val time.Time) zapcore.Field   { return zap.Time(key, val) }
func String(key string, val string) zapcore.Field    { return zap.String(key, val) }
func Strings(key string, val []string) zapcore.Field { return zap.Strings(key, val) }
func Bool(key string, val bool) zapcore.Field        { return zap.Bool(key, val) }
func Int(key string, val int) zapcore.Field          { return zap.Int(key, val) }
func Int64(key string, val int64) zapcore.Field      { return zap.Int64(key, val) }
func Float64(key string, val float64) zapcore.Field  { return zap.Float64(key, val) }
func MapStr(key string, val map[string]string) zapcore.Field {
	return zapcore.Field{
		Key:       key,
		Type:      zapcore.ObjectMarshalerType,
		Interface: mapStr(val),
	}
}

type mapStr map[string]string

func (m mapStr) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, v := range m {
		enc.AddString(k, v)
	}
	return nil
}
