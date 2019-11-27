# Copyright (c) 2020 OpenStack Foundation.
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

from swift3.response import AccessDenied

from oioiam.rule import Resource, RulesParsing, EXPLICIT_ALLOW, EXPLICIT_DENY, NOT_FOUND

def check_iam_access(action):
    def real_check_iam_access(func):
        def wrapper(*args, **kwargs):
            req = args[1]
            # FIXME a * must be used as object name,
            # not as wildcard in Resource below
            if req.object_name:
                rsc = Resource(req.container_name + '/' + req.object_name)
            elif req.container:
                rsc = Resource(req.container_name)
            else:
                rsc = None

            r = RulesParsing(req.iam_rules, rsc, action)
            a = r.run()
            # TODO add log to show matched rule if any (with its name)
            if a[0] != EXPLICIT_ALLOW:
                raise AccessDenied()

            return func(*args, **kwargs)
        return wrapper
    return real_check_iam_access
