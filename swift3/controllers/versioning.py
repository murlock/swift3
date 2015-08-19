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

from swift3.controllers.base import Controller, bucket_operation
from swift3.etree import (Element, tostring, SubElement, XMLSyntaxError,
                          DocumentInvalid, fromstring)
from swift3.response import HTTPOk, S3NotImplemented
from swift.common.utils import split_path
from swift.common.http import HTTP_CREATED, HTTP_ACCEPTED
MAX_PUT_VERSION_BODY_SIZE = 1024


class VersioningController(Controller):
    """
    Handles the following APIs:

     - GET Bucket versioning
     - PUT Bucket versioning

    Those APIs are logged as VERSIONING operations in the S3 server log.
    """
    @bucket_operation
    def GET(self, req):
        """
        Handles GET Bucket versioning.
        """
        elem = Element('VersioningConfiguration')

        try:
            if req.get_container_info(self.app)['versions']:
                SubElement(elem, "Status").text = "Enabled"
        except KeyError:
            pass

        body = tostring(elem)

        return HTTPOk(body=body, content_type="text/plain")

    @bucket_operation
    def PUT(self, req):
        """
        Handles PUT Bucket versioning.
        """
        xml = req.xml(MAX_PUT_VERSION_BODY_SIZE)

        if xml:
            try:
                elem = fromstring(xml, 'VersioningConfiguration')

                if (elem.find('Status').text) == "Enabled":

                    try:
                        if req.get_container_info(self.app)['versions']:
                            # Versioning already enabled
                            # TODO: Confirm that this is the correct behaviour
                            return HTTPOk()
                    except KeyError:
                        pass

                    # Add versions bucket.
                    new_path = split_path(req.path)[-1] + '+versions'

                    create_versions_req = req.to_swift_req(None, new_path, None)
                    create_versions_resp = create_versions_req.get_response(self.app)

                    if create_versions_resp.status_int == HTTP_CREATED or create_versions_resp.status_int == HTTP_ACCEPTED:
                        # Update container to indicate it's versioned
                        update_metadata_request = req.to_swift_req('PUT', split_path(req.path)[-1], None)
                        update_metadata_request.environ['HTTP_X_VERSIONS_LOCATION'] = new_path

                        update_metadata_resp = update_metadata_request.get_response(self.app)
                        # Should we just be looking for a 202 fom Swift on this metadata update?
                        if update_metadata_resp.status_int == HTTP_CREATED or update_metadata_resp.status_int == HTTP_ACCEPTED:
                            return HTTPOk()

                        # Internal server error here?

                    else:
                        pass
                        # Unable to create versions bucket
                        # Figure out behaviour if this fails?  Internal Server error?

                if (elem.find('Status').text) == "Suspended":
                    raise S3NotImplemented("Bucket versioning suspended state is not supported.")
            except (XMLSyntaxError, DocumentInvalid):
                # return error on bad input?
                pass

        return HTTPOk()
