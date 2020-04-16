from xml.etree import ElementTree
import configparser
import requests

accessToken = ""


def main():
    config = configparser.ConfigParser()
    config.read('folder.properties')

    user_domain = config['Section']['user.domain']
    user_name = config['Section']['user.username']
    user_password = config['Section']['user.password']
    user_tenant = config['Section']['user.tenant']
    parent = config['Section']['parent.folder']

    if not user_domain:
        print("Please enter the Preservica domain in the properties file")
        print("e.g. \"us\", \"eu\", \"ca\", \"au\" ")
        raise SystemExit

    if not user_name:
        print("Please enter the Preservica user name in the properties file")
        print("e.g. email address")
        raise SystemExit

    if not user_password:
        print("Please enter the Preservica password in the properties file")
        raise SystemExit

    if not user_tenant:
        print("Please enter the Preservica tenant name in the properties file")
        raise SystemExit

    if not parent:
        print("Please enter the reference id for the parent folder of the assets")
        raise SystemExit

    global accessToken
    accessToken = new_token(username=user_name, password=user_password, tenant=user_tenant, prefix=user_domain)

    title = get_folder_name(token=accessToken, username=user_name, password=user_password, tenant=user_tenant,
                            prefix=user_domain, folder_ref=parent)

    find_folders(parent=parent, token=accessToken, username=user_name, password=user_password,
                 tenant=user_tenant, prefix=user_domain, title=title)


def new_token(username, password, tenant, prefix):
    resp = requests.post(
        f'https://{prefix}.preservica.com/api/accesstoken/login?username={username}&password={password}&tenant={tenant}')
    if resp.status_code == 200:
        return resp.json()['token']
    else:
        print(f"new_token failed with error code: {resp.status_code}")
        print(resp.request.url)
        raise SystemExit


def get_folder_children(token, username, password, tenant, prefix, folder_ref):
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Preservica-Access-Token': token}
    so_request = requests.get(
        f'https://{prefix}.preservica.com/api/entity/structural-objects/{folder_ref}/children?start=0&max=100',
        headers=headers)
    if so_request.status_code == 401:
        global accessToken
        accessToken = new_token(username, password, tenant, prefix)
        return get_folder_children(accessToken, username, password, tenant, prefix, folder_ref)
    elif so_request.status_code == 200:
        xml_response = str(so_request.content.decode('UTF-8'))
        entity_response = ElementTree.fromstring(xml_response)
        children = entity_response.findall('.//{http://preservica.com/EntityAPI/v6.0}Child')
        paging = entity_response.findall('.//{http://preservica.com/EntityAPI/v6.0}Paging')
        return paging[0][0].text, children
    else:
        print(f"get_folder_name failed with error code: {so_request.status_code}")
        print(so_request.request.url)
        raise SystemExit


def get_folder_name(token, username, password, tenant, prefix, folder_ref):
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Preservica-Access-Token': token}
    so_request = requests.get(f'https://{prefix}.preservica.com/api/entity/structural-objects/{folder_ref}',
                              headers=headers)
    if so_request.status_code == 401:
        global accessToken
        accessToken = new_token(username, password, tenant, prefix)
        return get_folder_name(accessToken, username, password, tenant, prefix, folder_ref)
    elif so_request.status_code == 200:
        xml_response = str(so_request.content.decode('UTF-8'))
        entity_response = ElementTree.fromstring(xml_response)
        entity_title = entity_response.find('.//{http://preservica.com/XIP/v6.0}Title')
        return entity_title.text
    else:
        print(f"get_folder_name failed with error code: {so_request.status_code}")
        print(so_request.request.url)
        raise SystemExit


def get_representation(token, username, password, tenant, prefix, url):
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Preservica-Access-Token': token}
    request = requests.get(url, headers=headers)
    if request.status_code == 401:
        global accessToken
        accessToken = new_token(username, password, tenant, prefix)
        return get_representation(accessToken, username, password, tenant, prefix, url)
    elif request.status_code == 200:
        xml_response = str(request.content.decode('UTF-8'))
        representation_response = ElementTree.fromstring(xml_response)
        contentobject = representation_response.find('.//{http://preservica.com/EntityAPI/v6.0}ContentObject')
        if contentobject.text:
            return get_contentobject(token, username, password, tenant, prefix, contentobject.text)
        else:
            return None
    else:
        print(f"get_Representation failed with error code: {request.status_code}")
        print(request.request.url)
        raise SystemExit


def get_generation(token, username, password, tenant, prefix, url):
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Preservica-Access-Token': token}
    request = requests.get(url, headers=headers)
    if request.status_code == 401:
        global accessToken
        accessToken = new_token(username, password, tenant, prefix)
        return get_generation(accessToken, username, password, tenant, prefix, url)
    elif request.status_code == 200:
        xml_response = str(request.content.decode('UTF-8'))
        generation_response = ElementTree.fromstring(xml_response)
        bitstream = generation_response.find('.//{http://preservica.com/EntityAPI/v6.0}Bitstream')
        if bitstream.attrib['filename']:
            return bitstream.attrib['filename']
        else:
            return None
    else:
        print(f"get_generation failed with error code: {request.status_code}")
        print(request.request.url)
        raise SystemExit


def get_generations(token, username, password, tenant, prefix, url):
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Preservica-Access-Token': token}
    request = requests.get(url, headers=headers)
    if request.status_code == 401:
        global accessToken
        accessToken = new_token(username, password, tenant, prefix)
        return get_generations(accessToken, username, password, tenant, prefix, url)
    elif request.status_code == 200:
        xml_response = str(request.content.decode('UTF-8'))
        generations_response = ElementTree.fromstring(xml_response)
        generation = generations_response.find('.//{http://preservica.com/EntityAPI/v6.0}Generation')
        if generation.text:
            return get_generation(token, username, password, tenant, prefix, generation.text)
        else:
            return None
    else:
        print(f"get_generations failed with error code: {request.status_code}")
        print(request.request.url)
        raise SystemExit


def get_contentobject(token, username, password, tenant, prefix, url):
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Preservica-Access-Token': token}
    request = requests.get(url, headers=headers)
    if request.status_code == 401:
        global accessToken
        accessToken = new_token(username, password, tenant, prefix)
        return get_contentobject(accessToken, username, password, tenant, prefix, url)
    elif request.status_code == 200:
        xml_response = str(request.content.decode('UTF-8'))
        entity_response = ElementTree.fromstring(xml_response)
        generations = entity_response.find('.//{http://preservica.com/EntityAPI/v6.0}Generations')
        if generations.text:
            return get_generations(token, username, password, tenant, prefix, generations.text)
        else:
            return None
    else:
        print(f"get_contentobject failed with error code: {request.status_code}")
        print(request.request.url)
        raise SystemExit


def get_representations(token, username, password, tenant, prefix, url):
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Preservica-Access-Token': token}
    request = requests.get(url, headers=headers)
    if request.status_code == 401:
        global accessToken
        accessToken = new_token(username, password, tenant, prefix)
        return get_representations(accessToken, username, password, tenant, prefix, url)
    elif request.status_code == 200:
        xml_response = str(request.content.decode('UTF-8'))
        representations_response = ElementTree.fromstring(xml_response)
        representation = representations_response.find('.//{http://preservica.com/EntityAPI/v6.0}Representation')
        if representation.text:
            return get_representation(token, username, password, tenant, prefix, representation.text)
        else:
            return None
    else:
        print(f"get_Representations failed with error code: {request.status_code}")
        print(request.request.url)
        raise SystemExit


def get_entity(token, username, password, tenant, prefix, ref):
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Preservica-Access-Token': token}
    so_request = requests.get(f'https://{prefix}.preservica.com/api/entity/information-objects/{ref}',
                              headers=headers)
    if so_request.status_code == 401:
        global accessToken
        accessToken = new_token(username, password, tenant, prefix)
        return get_entity(accessToken, username, password, tenant, prefix, ref)
    elif so_request.status_code == 200:
        xml_response = str(so_request.content.decode('UTF-8'))
        io = ElementTree.fromstring(xml_response)
        representations = io.find('.//{http://preservica.com/EntityAPI/v6.0}Representations')
        if representations.text:
            return get_representations(token, username, password, tenant, prefix, representations.text)
        else:
            return None
    else:
        print(f"get_entity failed with error code: {so_request.status_code}")
        print(so_request.request.url)
        raise SystemExit


def update_asset_description(ref, token, username, password, tenant, prefix, title):
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Preservica-Access-Token': token}
    get_request = requests.get(f'https://{prefix}.preservica.com/api/entity/information-objects/{ref}',
                               headers=headers)
    if get_request.status_code == 401:
        global accessToken
        accessToken = new_token(username, password, tenant, prefix)
        return update_asset_description(accessToken, username, password, tenant, prefix, ref)
    elif get_request.status_code == 200:
        xml_response = str(get_request.content.decode('UTF-8'))
        asset = ElementTree.fromstring(xml_response)
        io = asset.find('.//{http://preservica.com/XIP/v6.0}InformationObject')
        description = asset.find('.//{http://preservica.com/XIP/v6.0}Description')
        if description is None:
            description = ElementTree.Element("{http://preservica.com/XIP/v6.0}Description")
            description.text = title
            io.insert(2, description)
        else:
            print(f'Found existing description "{description.text}"')
            if description.text == title:
                print(f'existing description OK, nothing to do....')
                return
            else:
                print(f'Changing description to "{title}"')
                description.text = title
        xml = ElementTree.tostring(io, 'utf-8').decode('utf-8')
        data = bytes(xml, 'utf-8')
        headers = {'Content-Type': 'application/xml', 'Preservica-Access-Token': token}
        put = requests.put(f'https://{prefix}.preservica.com/api/entity/information-objects/{ref}',
                           data=data, headers=headers)
        if put.status_code == 200:
            print("Asset Description Updated")
        else:
            print(put.status_code)
            raise SystemExit
    else:
        print(f"update_asset_description failed with error code: {get_request.status_code}")
        print(get_request.request.url)
        raise SystemExit


def find_folders(parent, token, username, password, tenant, prefix, title):
    print(f'Finding entities inside folder: {title}')
    tupl = get_folder_children(token=token, username=username, password=password, tenant=tenant,
                               prefix=prefix, folder_ref=parent)
    max_results = tupl[0]
    children = tupl[1]
    for child in children:
        if child.attrib['type'] == 'SO':
            find_folders(child.attrib['ref'], token, username, password, tenant, prefix, child.attrib["title"])
        if child.attrib['type'] == 'IO':
            filename = get_entity(token, username, password, tenant, prefix, child.attrib["ref"])
            print(f'Found entity: "{child.attrib["title"]}" '
                  f'with ref: "{child.attrib["ref"]}" with filename: "{filename}"')
            if filename:
                update_asset_description(child.attrib["ref"], token, username, password, tenant, prefix, filename)


main()
