from re import search


def is_amazon_s3_server(server):
    version = bool(search(r'\d', server))

    return version and 'AmazonS3' in server
