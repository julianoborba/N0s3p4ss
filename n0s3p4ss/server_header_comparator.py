from packaging import version


def is_amazon_s3(server_header):
    return 'AmazonS3' in server_header


def compare_nginx_version(server_header, nginx_version_number):
    server_header_parts = server_header.split('nginx/')
    if len(server_header_parts) < 2:
        return ''

    server_version = server_header_parts[1]

    if version.parse(server_version) < version.parse(nginx_version_number):
        return (f'The server Nginx version is lesser than Nginx expected '
                f'version; The expected version is {nginx_version_number}')

    return ('The server Nginx version is the same as the expected Nginx '
            f'version; The expected version is {nginx_version_number}')
