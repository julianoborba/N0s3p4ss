from marshmallow import Schema
from marshmallow.fields import Str, Int, List, Bool, Date, Nested


class CertificateInformationsSchema(Schema):
    issuer = Str()
    expiration = Date()


class ReportSchema(Schema):
    subdomain = Str()
    url = Str()
    ip = Str()
    status = Int()
    cert_info = Nested(CertificateInformationsSchema())
    server = Str()
    tor = Bool()
    waf = List(Str())
    open_ports = List(Int())
    alerts = List(Str())
    score = Int()
