# Copyright (c) 2010-2014 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from base64 import standard_b64encode as b64encode
from base64 import standard_b64decode as b64decode

from swift.common.http import HTTP_OK
from swift.common.middleware.versioned_writes import DELETE_MARKER_CONTENT_TYPE
from swift.common.utils import json, public, config_true_value

from swift3.controllers.base import Controller
from swift3.controllers.cors import get_cors, cors_fill_headers, \
    CORS_ALLOWED_HTTP_METHOD
from swift3.etree import Element, SubElement, tostring, fromstring, \
    XMLSyntaxError, DocumentInvalid
from swift3.iam import check_iam_access
from swift3.response import HTTPOk, S3NotImplemented, InvalidArgument, \
    MalformedXML, InvalidLocationConstraint, NoSuchBucket, \
    BucketNotEmpty, InternalError, ServiceUnavailable, NoSuchKey, \
    CORSForbidden, CORSInvalidAccessControlRequest, CORSOriginMissing, \
    BucketAlreadyExists
from swift3.cfg import CONF
from swift3.utils import LOGGER, MULTIUPLOAD_SUFFIX, VERSIONING_SUFFIX, \
    extract_s3_etag, log_s3api_command

MAX_PUT_BUCKET_BODY_SIZE = 10240


class BucketController(Controller):
    """
    Handles bucket request.
    """
    def _delete_segments_bucket(self, req):
        """
        Before delete bucket, delete segments bucket if existing.
        """
        container = req.container_name + MULTIUPLOAD_SUFFIX
        marker = ''
        seg = ''

        try:
            resp = req.get_response(self.app, 'HEAD')
            if int(resp.sw_headers['X-Container-Object-Count']) > 0:
                raise BucketNotEmpty()
            # FIXME: This extra HEAD saves unexpected segment deletion
            # but if a complete multipart upload happen while cleanup
            # segment container below, completed object may be missing its
            # segments unfortunately. To be safer, it might be good
            # to handle if the segments can be deleted for each object.
        except NoSuchBucket:
            pass

        try:
            while True:
                # delete all segments
                resp = req.get_response(self.app, 'GET', container,
                                        query={'format': 'json',
                                               'marker': marker})
                segments = json.loads(resp.body)
                for seg in segments:
                    try:
                        req.get_response(self.app, 'DELETE', container,
                                         seg['name'].encode('utf-8'))
                    except NoSuchKey:
                        pass
                    except InternalError:
                        raise ServiceUnavailable()
                if segments:
                    marker = seg['name']
                else:
                    break
            req.get_response(self.app, 'DELETE', container)
        except NoSuchBucket:
            return
        except (BucketNotEmpty, InternalError):
            raise ServiceUnavailable()

    @public
    @check_iam_access("s3:ListBucket")
    def HEAD(self, req):
        """
        Handle HEAD Bucket (Get Metadata) request
        """
        log_s3api_command(req, 'head-bucket')

        resp = req.get_response(self.app)

        return HTTPOk(headers=resp.headers)

    @public
    @check_iam_access("s3:ListBucket")
    def GET(self, req):
        """
        Handle GET Bucket (List Objects) request
        """

        max_keys = req.get_validated_param('max-keys', CONF.max_bucket_listing)
        # TODO: Separate max_bucket_listing and default_bucket_listing
        tag_max_keys = max_keys
        max_keys = min(max_keys, CONF.max_bucket_listing)

        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        query = {
            'format': 'json',
            'limit': max_keys + 1,
        }
        if 'marker' in req.params:
            query.update({'marker': req.params['marker']})
        if 'prefix' in req.params:
            query.update({'prefix': req.params['prefix']})
        if 'delimiter' in req.params:
            query.update({'delimiter': req.params['delimiter']})

        # GET Bucket (List Objects) Version 2 parameters
        is_v2 = int(req.params.get('list-type', '1')) == 2
        fetch_owner = False
        if is_v2:
            log_s3api_command(req, 'list-objects-v2')
            if 'start-after' in req.params:
                query.update({'marker': req.params['start-after']})
            # continuation-token overrides start-after
            if 'continuation-token' in req.params:
                decoded = b64decode(req.params['continuation-token'])
                query.update({'marker': decoded})
            if 'fetch-owner' in req.params:
                fetch_owner = config_true_value(req.params['fetch-owner'])
        else:
            log_s3api_command(req, 'list-objects')

        resp = req.get_response(self.app, query=query)

        objects = json.loads(resp.body)

        if 'versions' in req.params:
            req.container_name += VERSIONING_SUFFIX
            query['reverse'] = 'true'
            try:
                resp = req.get_response(self.app, query=query)
                versioned_objects = json.loads(resp.body)
                prefixes = set()
                for o in versioned_objects:
                    if 'name' in o:
                        # The name looks like this:
                        #  '%03x%s/%s' % (len(name), name, version)
                        o['name'], o['version_id'] = \
                            o['name'][3:].rsplit('/', 1)
                    else:
                        prefixes.add(o['subdir'])
                # suppress duplicated prefixes
                for o in list(objects):
                    if 'subdir' in o and o['subdir'] in prefixes:
                        objects.remove(o)
                objects.extend(versioned_objects)
            except NoSuchBucket:
                # the bucket may not be versioned
                pass
            req.container_name = req.container_name[:-len(VERSIONING_SUFFIX)]
            objects.sort(key=lambda o: o.get('name') or o.get('subdir'))
            for o in objects:
                if 'subdir' not in o and not o.get('version_id'):
                    info = req.get_object_info(
                        self.app, object_name=o['name'].encode('utf-8'))
                    o['sysmeta_version_id'] = info.get('sysmeta', {}).get(
                        'version-id', 'null')

        if 'versions' in req.params:
            elem = Element('ListVersionsResult')
        else:
            elem = Element('ListBucketResult')

        if encoding_type is not None:
            elem.encoding_type = encoding_type

        SubElement(elem, 'Name').text = req.container_name
        SubElement(elem, 'Prefix').text = req.params.get('prefix')

        # Filter objects according to version-id-marker and key-marker
        v_marker = req.params.get('version-id-marker')
        k_marker = req.params.get('key-marker')
        k_marker_matched = not bool(k_marker)
        if 'versions' in req.params and (v_marker or k_marker):
            to_delete = []
            for i, o in enumerate(objects):
                if 'subdir' not in o:
                    version_id = o.get('version_id',
                                       o.get('sysmeta_version_id', 'null'))

                    if not k_marker_matched and k_marker != o['name']:
                        to_delete.append(i)
                    if k_marker == o['name']:
                        k_marker_matched = True

                    if k_marker == o['name'] and v_marker:

                        if v_marker == version_id:
                            v_marker = None
                        to_delete.append(i)
            for i in reversed(to_delete):
                objects.pop(i)

        # in order to judge that truncated is valid, check whether
        # max_keys + 1 th element exists in swift.
        is_truncated = max_keys > 0 and len(objects) > max_keys
        objects = objects[:max_keys]

        if not is_v2:
            if 'versions' in req.params:
                SubElement(elem, 'KeyMarker').text = req.params.get(
                    'key-marker')
                SubElement(elem, 'VersionIdMarker').text = req.params.get(
                    'version-id-marker')
            else:
                SubElement(elem, 'Marker').text = req.params.get('marker')
            if is_truncated and 'delimiter' in req.params:
                if 'name' in objects[-1]:
                    SubElement(elem, 'NextMarker').text = \
                        objects[-1]['name']
                if 'subdir' in objects[-1]:
                    SubElement(elem, 'NextMarker').text = \
                        objects[-1]['subdir']
        else:
            if is_truncated:
                if 'name' in objects[-1]:
                    SubElement(elem, 'NextContinuationToken').text = \
                        b64encode(objects[-1]['name'].encode('utf8'))
                if 'subdir' in objects[-1]:
                    SubElement(elem, 'NextContinuationToken').text = \
                        b64encode(objects[-1]['subdir'].encode('utf8'))
            if 'continuation-token' in req.params:
                SubElement(elem, 'ContinuationToken').text = \
                    req.params['continuation-token']
            if 'start-after' in req.params:
                SubElement(elem, 'StartAfter').text = \
                    req.params['start-after']
            SubElement(elem, 'KeyCount').text = str(len(objects))

        SubElement(elem, 'MaxKeys').text = str(tag_max_keys)

        if 'delimiter' in req.params:
            SubElement(elem, 'Delimiter').text = req.params['delimiter']

        if encoding_type is not None:
            SubElement(elem, 'EncodingType').text = encoding_type

        SubElement(elem, 'IsTruncated').text = \
            'true' if is_truncated else 'false'

        for o in objects:
            if 'subdir' not in o:
                if 'versions' in req.params:
                    version_id = o.get('version_id',
                                       o.get('sysmeta_version_id', 'null'))

                    if o.get('content_type') == DELETE_MARKER_CONTENT_TYPE:
                        contents = SubElement(elem, 'DeleteMarker')
                    else:
                        contents = SubElement(elem, 'Version')
                    SubElement(contents, 'Key').text = \
                        o['name'].encode('utf-8')
                    SubElement(contents, 'VersionId').text = version_id
                    SubElement(contents, 'IsLatest').text = str(
                        'version_id' not in o).lower()
                else:
                    contents = SubElement(elem, 'Contents')
                    SubElement(contents, 'Key').text = \
                        o['name'].encode('utf-8')
                SubElement(contents, 'LastModified').text = \
                    o['last_modified'][:-3] + 'Z'
                if 's3_etag' in o.get('content_type', ''):
                    _, o['hash'] = extract_s3_etag(o['content_type'])
                if contents.tag != 'DeleteMarker':
                    SubElement(contents, 'ETag').text = '"%s"' % o['hash']
                    SubElement(contents, 'Size').text = str(o['bytes'])
                if fetch_owner or not is_v2:
                    owner = SubElement(contents, 'Owner')
                    SubElement(owner, 'ID').text = req.user_id
                    SubElement(owner, 'DisplayName').text = req.user_id
                if contents.tag != 'DeleteMarker':
                    SubElement(contents, 'StorageClass').text = 'STANDARD'

        for o in objects:
            if 'subdir' in o:
                common_prefixes = SubElement(elem, 'CommonPrefixes')
                SubElement(common_prefixes, 'Prefix').text = \
                    o['subdir'].encode('utf-8')

        body = tostring(elem, encoding_type=encoding_type)

        resp = HTTPOk(body=body, content_type='application/xml')

        origin = req.headers.get('Origin')
        if origin:
            rule = get_cors(self.app, req, "GET", origin)
            if rule:
                cors_fill_headers(req, resp, rule)

        return resp

    @public
    @check_iam_access("s3:CreateBucket")
    def PUT(self, req):
        """
        Handle PUT Bucket request
        """
        log_s3api_command(req, 'create-bucket')
        xml = req.xml(MAX_PUT_BUCKET_BODY_SIZE)
        if xml:
            # check location
            try:
                elem = fromstring(xml, 'CreateBucketConfiguration')
                location = elem.find('./LocationConstraint').text
            except (XMLSyntaxError, DocumentInvalid):
                raise MalformedXML()
            except Exception as e:
                LOGGER.error(e)
                raise

            if location != CONF.location:
                # Swift3 cannot support multiple regions currently.
                raise InvalidLocationConstraint()

        resp = req.get_response(self.app)

        # create bucket+segments to avoid breaking
        # functional tests for swift3
        try:
            cnt = req.container_name + MULTIUPLOAD_SUFFIX
            req.get_response(self.app, 'PUT', cnt, '')
        except BucketAlreadyExists:
            pass

        resp.status = HTTP_OK
        resp.location = '/' + req.container_name

        return resp

    @public
    @check_iam_access("s3:DeleteBucket")
    def DELETE(self, req):
        """
        Handle DELETE Bucket request
        """
        log_s3api_command(req, 'delete-bucket')
        if CONF.allow_multipart_uploads:
            self._delete_segments_bucket(req)
        resp = req.get_response(self.app)
        return resp

    @public
    def POST(self, req):
        """
        Handle POST Bucket request
        """
        raise S3NotImplemented()

    @public
    def OPTIONS(self, req):
        log_s3api_command(req, 'options')
        origin = req.headers.get('Origin')
        if not origin:
            raise CORSOriginMissing()

        method = req.headers.get('Access-Control-Request-Method')
        if method not in CORS_ALLOWED_HTTP_METHOD:
            raise CORSInvalidAccessControlRequest(method=method)

        rule = get_cors(self.app, req, method, origin)
        # FIXME(mbo): we should raise also NoSuchCORSConfiguration
        if rule is None:
            raise CORSForbidden(method)

        resp = HTTPOk(body=None)
        del resp.headers['Content-Type']

        return cors_fill_headers(req, resp, rule)
