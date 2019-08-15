from re import search


def is_amazon_s3_server(server):
    version = bool(search(r'\d', server))

    return version and 'AmazonS3' in server


def compare_nginx_version(server, nginx_version):
    server_version = str((server.split('nginx/'))[1])

    if server_version < nginx_version:
        return ('The server nginx version is lesser than nginx expected \
version; The expected version is {}'.format(nginx_version))

    return ('The server nginx version is the same as expected \
version; The expected version is {}'.format(nginx_version))
