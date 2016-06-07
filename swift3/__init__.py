# Copyright (c) 2012-2014 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pkg_resources

__all__ = ['version_info', 'version']

__version__ = '1.10.0.5'

#: Version information ``(major, minor, revision)``.
version_info = tuple(map(int, __version__.split('.')[:3]))
#: Version string ``'major.minor.revision'``.
version = '.'.join(map(str, version_info))
