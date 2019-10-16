from marshmallow import Schema
from marshmallow.fields import Str, Int, List, Bool, Nested


class CertificateInformationsSchema(Schema):
    issuer = Str()
    expiration = Str()


class ReportSchema(Schema):
    subdomain = Str()
    url = Str()
    ip = Str()
    status = Int()
    cert_info = Nested(CertificateInformationsSchema())
    server = Str()
    tor_reachable = Bool()
    detected_waf = List(Str())
    open_ports = List(Int())
    alerts = List(Str())
