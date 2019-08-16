def is_amazon_s3(server_header):
    return 'AmazonS3' in server_header


def compare_nginx_version(server_header, nginx_version_number):
    server_version_number = str((server_header.split('nginx/'))[1])

    if server_version_number < nginx_version_number:
        return (f'The server Nginx version is lesser than Nginx expected '
                f'version; The expected version is {nginx_version_number}')

    return ('The server Nginx version is the same as the expected Nginx '
            f'version; The expected version is {nginx_version_number}')
