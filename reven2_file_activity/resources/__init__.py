"""Resources

  - msdn.xml: Windows API from msdn
  - msdn-type.conf: typedefs required to parse msdn.xml prototypes
"""
import os.path

resources_path = os.path.dirname(__file__)

msdn_xml = os.path.join(resources_path, "msdn.xml")
msdn_typedefs_conf = os.path.join(resources_path, "msdn-types.conf")
