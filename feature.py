import re
import socket
import requests
import whois
import ssl
from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc
        self.response = None
        self.whois_response = None
        self.features = []

        try:
            self.response = requests.get(url, timeout=5, allow_redirects=True)
        except:
            self.response = None

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None

        # Extract all 30 features and store them
        self.features = [
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbolAt(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.Https(),
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.RequestURL(),
            self.AnchorURL(),
            self.LinksInScriptTags(),
            self.ServerFormHandler(),
            self.InfoEmail(),
            self.AbnormalURL(),
            self.WebsiteForwarding(),
            self.StatusBarCust(),
            self.DisableRightClick(),
            self.UsingPopupWindow(),
            self.IframeRedirection(),
            self.AgeofDomain(),
            self.DNSRecording(),
            self.WebsiteTraffic(),
            self.PageRank(),
            self.GoogleIndex(),
            self.LinksPointingToPage(),
            self.StatsReport()
        ]

    def UsingIp(self):
        match = re.search(r'(\\d{1,3}\\.){3}\\d{1,3}', self.url)
        return -1 if match else 1

    def longUrl(self):
        return -1 if len(self.url) >= 75 else 1

    def shortUrl(self):
        shorteners = ["bit.ly", "goo.gl", "tinyurl", "t.co"]
        return -1 if any(s in self.url for s in shorteners) else 1

    def symbolAt(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.count("//") > 1 else 1

    def prefixSuffix(self):
        return -1 if "-" in self.domain else 1

    def SubDomains(self):
        return -1 if self.domain.count(".") > 2 else 1

    def Https(self):
        return 1 if self.url.startswith("https://") else -1

    def DomainRegLen(self):
        try:
            exp = self.whois_response.expiration_date
            if isinstance(exp, list):
                exp = exp[0]
            return 1 if (exp.year - date.today().year) >= 1 else -1
        except:
            return -1

    def Favicon(self): return 1
    def NonStdPort(self): return 1
    def HTTPSDomainURL(self): return 1
    def RequestURL(self): return 1
    def AnchorURL(self): return 1
    def LinksInScriptTags(self): return 1
    def ServerFormHandler(self): return 1
    def InfoEmail(self): return -1 if "mailto:" in self.url else 1

    def AbnormalURL(self):
        keywords = ["secure", "login", "verify", "update", "account", "confirm"]
        return -1 if any(k in self.url.lower() for k in keywords) else 1

    def WebsiteForwarding(self):
        return -1 if self.response and len(self.response.history) > 2 else 1

    def StatusBarCust(self): return 1
    def DisableRightClick(self): return 1
    def UsingPopupWindow(self): return 1
    def IframeRedirection(self): return 1

    def AgeofDomain(self):
        try:
            creation = self.whois_response.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            age_months = (date.today().year - creation.year) * 12 + (date.today().month - creation.month)
            return 1 if age_months >= 6 else -1
        except:
            return -1

    def DNSRecording(self): return 1
    def WebsiteTraffic(self): return 1
    def PageRank(self): return 1
    def GoogleIndex(self): return 1
    def LinksPointingToPage(self): return 1
    def StatsReport(self): return 1

    def getDomainAge(self):
        try:
            creation = self.whois_response.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            return (date.today().year - creation.year) * 12 + (date.today().month - creation.month)
        except:
            return -1

    def getGeoLocation(self):
        try:
            ip = socket.gethostbyname(self.domain)
            response = requests.get(f"http://ipinfo.io/{ip}/json", timeout=5).json()
            country = response.get("country", "Unknown")
            org = response.get("org", "Unknown")
            return f"{org}, {country}"
        except:
            return "Unknown"

    def getRiskScore(self):
        total = len(self.features)
        risky = sum(1 for f in self.features if f == -1)
        if any(k in self.url.lower() for k in ["secure-login", "paypal", "verify", "update"]):
            risky += 3
        return round((risky / total) * 100, 2)

    def getSSLInfo(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert["issuer"])
                    return f"Valid SSL issued by {issuer.get('organizationName', 'Unknown')}"
        except:
            return "No valid SSL certificate"

    def getReasons(self):
        reasons = []
        if self.UsingIp() == -1: reasons.append("Uses IP address instead of domain")
        if self.longUrl() == -1: reasons.append("URL length is suspiciously long")
        if self.shortUrl() == -1: reasons.append("Uses a URL shortener")
        if self.prefixSuffix() == -1: reasons.append("Domain contains '-' which is unusual")
        if self.SubDomains() == -1: reasons.append("Too many subdomains")
        if self.AbnormalURL() == -1: reasons.append("Contains suspicious keyword like login/verify/update")
        if self.AgeofDomain() == -1: reasons.append("Domain is too new")
        if self.WebsiteForwarding() == -1: reasons.append("Multiple redirects detected")
        return reasons if reasons else ["No major phishing signs detected"]

    def getRedirectChain(self):
        try:
            if self.response and self.response.history:
                return [r.url for r in self.response.history] + [self.response.url]
            return []
        except:
            return []

    def getFeaturesList(self):
        return self.features

    def debug_feature_vector(self):
        names = [
            "UsingIp", "LongUrl", "ShortUrl", "Symbol@", "Redirecting",
            "PrefixSuffix", "SubDomains", "HttpsInScheme", "DomainRegLen",
            "Favicon", "NonStdPort", "HTTPSInDomain", "RequestURL", "AnchorURL",
            "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL",
            "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
            "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
            "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage",
            "StatsReport"
        ]
        return list(zip(names, self.features))
