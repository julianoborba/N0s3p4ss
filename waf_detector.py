from wafw00f import main


def detect(url, port, ssl):
    result = main.WafW00F(
        target=url,
        port=port,
        ssl=ssl,
        debuglevel=0,
        path='/',
        followredirect=True,
        extraheaders={},
        proxy='http://10.154.11.143:8888'
    ).identwaf(True)

    return result
