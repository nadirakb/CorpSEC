"""CorpSEC check catalog (spec §6), grouped by area."""

from corpsec_checks.connection.conn_001 import HttpsReachable
from corpsec_checks.connection.conn_002 import HttpRedirectsToHttps
from corpsec_checks.connection.conn_003 import ApexAndWwwAgree
from corpsec_checks.connection.conn_004 import NoMixedContent
from corpsec_checks.connection.crawl_001 import Crawler
from corpsec_checks.exposure.exp_001 import GitExposed
from corpsec_checks.exposure.exp_002 import EnvFileExposed
from corpsec_checks.exposure.exp_003 import WpConfigBackupExposed
from corpsec_checks.exposure.exp_004 import BackupArchiveExposed
from corpsec_checks.exposure.exp_005 import PhpInfoExposed
from corpsec_checks.exposure.exp_006 import DsStoreExposed
from corpsec_checks.exposure.exp_007 import ServerStatusExposed
from corpsec_checks.exposure.exp_008 import OtherVcsExposed
from corpsec_checks.exposure.exp_009 import DebugLogExposed
from corpsec_checks.mail.dns_001 import DomainExpiry
from corpsec_checks.mail.dns_002 import Dnssec
from corpsec_checks.mail.dns_003 import Caa
from corpsec_checks.mail.dns_004 import SubdomainTakeover
from corpsec_checks.mail.mail_001 import MailServers
from corpsec_checks.mail.mail_002 import SpfValid
from corpsec_checks.mail.mail_003 import SpfAllQualifier
from corpsec_checks.mail.mail_004 import DmarcPresent
from corpsec_checks.mail.mail_005 import DmarcEnforced
from corpsec_checks.mail.mail_006 import DkimFound
from corpsec_checks.mail.mail_007 import NonSendingDomainLocked
from corpsec_checks.mail.mail_008 import MtaSts
from corpsec_checks.software.sw_001 import PlatformDetected
from corpsec_checks.software.sw_002 import CmsUpToDate
from corpsec_checks.software.sw_003 import KnownVulnerableVersion
from corpsec_checks.software.sw_004 import VulnerablePlugins
from corpsec_checks.software.sw_005 import VulnerableJsLibraries
from corpsec_checks.software.sw_006 import EndOfLifeSoftware
from corpsec_checks.software.sw_007 import WordPressUserEnumeration
from corpsec_checks.software.sw_008 import WordPressXmlRpc
from corpsec_checks.tls.tls_001 import CertificateValid
from corpsec_checks.tls.tls_002 import CertificateExpiry
from corpsec_checks.tls.tls_003 import LegacyTlsDisabled
from corpsec_checks.tls.tls_004 import ModernTlsSupported
from corpsec_checks.tls.tls_005 import NoWeakCiphers
from corpsec_checks.tls.tls_006 import ForwardSecrecy
from corpsec_checks.tls.tls_007 import Hsts
from corpsec_checks.tls.tls_008 import CertificateKeyStrength
from corpsec_checks.website.ck_001 import CookieSecure
from corpsec_checks.website.ck_002 import CookieHttpOnly
from corpsec_checks.website.ck_003 import CookieSameSite
from corpsec_checks.website.cors_001 import CorsMisconfiguration
from corpsec_checks.website.dir_001 import DirectoryListing
from corpsec_checks.website.err_001 import VerboseErrors
from corpsec_checks.website.hdr_001 import ContentSecurityPolicy
from corpsec_checks.website.hdr_002 import ClickjackingProtection
from corpsec_checks.website.hdr_003 import NoSniff
from corpsec_checks.website.hdr_004 import ReferrerPolicy
from corpsec_checks.website.hdr_005 import PermissionsPolicy
from corpsec_checks.website.hdr_006 import VersionBanners
from corpsec_checks.website.sec_001 import SecurityTxt
from corpsec_scanner import Check

CHECKS: tuple[type[Check], ...] = (
    HttpsReachable,
    HttpRedirectsToHttps,
    ApexAndWwwAgree,
    NoMixedContent,
    Crawler,
    CertificateValid,
    CertificateExpiry,
    LegacyTlsDisabled,
    ModernTlsSupported,
    NoWeakCiphers,
    ForwardSecrecy,
    Hsts,
    CertificateKeyStrength,
    ContentSecurityPolicy,
    ClickjackingProtection,
    NoSniff,
    ReferrerPolicy,
    PermissionsPolicy,
    VersionBanners,
    CookieSecure,
    CookieHttpOnly,
    CookieSameSite,
    CorsMisconfiguration,
    DirectoryListing,
    VerboseErrors,
    SecurityTxt,
    PlatformDetected,
    CmsUpToDate,
    KnownVulnerableVersion,
    VulnerablePlugins,
    VulnerableJsLibraries,
    EndOfLifeSoftware,
    WordPressUserEnumeration,
    WordPressXmlRpc,
    GitExposed,
    EnvFileExposed,
    WpConfigBackupExposed,
    BackupArchiveExposed,
    PhpInfoExposed,
    DsStoreExposed,
    ServerStatusExposed,
    OtherVcsExposed,
    DebugLogExposed,
    DomainExpiry,
    Dnssec,
    Caa,
    SubdomainTakeover,
    MailServers,
    SpfValid,
    SpfAllQualifier,
    DmarcPresent,
    DmarcEnforced,
    DkimFound,
    NonSendingDomainLocked,
    MtaSts,
)

__all__ = ["CHECKS"]
