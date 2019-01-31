from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TEXT_FORMAT, TAG_WEIGHT, TAG_TYPE
from assemblyline.common.reaper import set_death_signal
from assemblyline.common.net import is_valid_domain, is_valid_email, is_valid_ip

import binwalk
import os
import zipfile


class Firmsplode(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'unknown'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_ENABLED = True
    SERVICE_STAGE = 'CORE'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 1024

    def __init__(self, cfg=None):
        super(Firmsplode, self).__init__(cfg)

    def start(self):
        self.log.debug("Firmsplode service started")

    def execute(self, request):
        local = request.download()
        al_result = Result()


        command = self.construct_command(request)

        request.task.set_milestone("started", True)

        extract_section = ResultSection(SCORE.NULL, 'Extracted and Carved Files')

        for module in binwalk.scan(local, **command):
            section = ResultSection(SCORE.NULL, module.name, body_format=TEXT_FORMAT.MEMORY_DUMP)
            for result in module.results:
                section.add_line("0x%.8X : %s" % (result.offset, result.description))

                if(module.extractor.output.has_key(result.file.path)):

                    if module.extractor.output[result.file.path].carved.has_key(result.offset):
                        extract_section.add_line("Carved data from offset 0x%X to %s" % (result.offset, module.extractor.output[result.file.path].carved[result.offset]))
                        file_name = module.extractor.output[result.file.path].carved[result.offset].split("/")[-1]
                        request.add_extracted(module.extractor.output[result.file.path].carved[result.offset], 'Carved File', file_name)

                    if module.extractor.output[result.file.path].extracted.has_key(result.offset) and \
                            len(module.extractor.output[result.file.path].extracted[result.offset].files) > 0:

                        path = module.extractor.output[result.file.path].extracted[result.offset].files[0]
                        extract = module.extractor.output[result.file.path].extracted[result.offset].command

                        extract_section.add_line("Extracted %d files from offset 0x%X to '%s' using '%s'" % (
                            len(module.extractor.output[result.file.path].extracted[result.offset].files),
                            result.offset,
                            path,
                            extract))

                        if(os.path.isdir(path)):
                            file = zipfile.ZipFile("%s.zip" % path.split("/")[-1], 'w', zipfile.ZIP_DEFLATED)
                            self.zip_dir(path, file)
                            file.close()
                            request.add_supplementary(file.filename, extract, file.filename.split("/")[-1])
                        else:
                            request.add_extracted(path, extract, path.split("/")[-1])

            al_result.add_section(section)

        request.task.set_milestone("finished", True)
        al_result.add_section(extract_section)
        request.result = al_result

    def zip_dir(self, path, ziph):
        for root, dirs, files in os.walk(path):
            for file in files:
                ziph.write(os.path.join(root, file))

    def construct_command(self, request):
        cmd = {}



        cmd['signature'] = True
        cmd['entropy'] = True
        cmd['directory'] = self.working_directory
        cmd['extract'] = True
        cmd['quiet'] = True

        return cmd

