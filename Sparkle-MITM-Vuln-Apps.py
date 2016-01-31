#!/usr/bin/python
"""
EA to get a list of all apps that are vulnerable to Sparkle MITM attacks
More information: https://macmule.com/2016/01/31/sparkle-updater-framework-http-man-in-the-middle-vulnerability
GitRepo: https://github.com/macmule/JSS-Extension-Attributes
License: http://macmule.com/license/
"""
import os
import subprocess
from CoreFoundation import CFPreferencesCopyAppValue
from distutils.version import LooseVersion

def get_vulnapps():
    """
    Get a list of apps with old Sparkle frameworks, and check SUFeedURL for http://
    If Sparkle framework version not found, adds to vulnerable list.
    """
    # Get all apps mdfind knows about
    apps = subprocess.check_output(['/usr/bin/mdfind', 'kind:app'])
    sparkle_info = '/Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Info.plist'
    app_info = '/Contents/Info.plist'
    vulnerableapp_list = []
    for app in apps.splitlines():
        # If the app has a sparkle framework
        if os.path.exists(app + sparkle_info):
            # Try to get a version out of Sparkle's framework, returns None without exception if missing
            sparkle_version = CFPreferencesCopyAppValue('CFBundleShortVersionString',
                                                        app + sparkle_info)
            if not sparkle_version:
                sparkle_version = CFPreferencesCopyAppValue('CFBundleVersion',
                                                            app + sparkle_info)
            # Check for a SUFeedURL
            sparkle_feed_url = CFPreferencesCopyAppValue('SUFeedURL',
                                                         app + app_info)
            bundle_id = CFPreferencesCopyAppValue('CFBundleIdentifier',
                                                         app + app_info)
            # If we have a SUFeedURL
            if sparkle_feed_url and not sparkle_feed_url.startswith('https://'):
                # If Sparkle version is less than 1.13.1 & SUFeedURL is http
                if not sparkle_version:
                    vulnerableapp_list.append(app + ' - ' + bundle_id)
                elif LooseVersion(sparkle_version) < LooseVersion('1.13.1'):
                    vulnerableapp_list.append(app + ' - ' + bundle_id)
    return vulnerableapp_list


def main():
    """For EA, print list of all vulnerable apps including file paths"""
    vulnerableapp_list = get_vulnapps()
    if len(vulnerableapp_list) > 0:
        result = "\n".join(*[vulnerableapp_list])
    else:
        result = 'None found'
    print '<result>%s</result>' % result


if __name__ == '__main__':
    main()
