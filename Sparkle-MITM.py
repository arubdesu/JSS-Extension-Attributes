#!/usr/bin/python
"""
EA to get a list of all apps that are vulnerable to Sparkle MITM attacks

More information: https://macmule.com/2016/01/31/sparkle-updater-framework-http-man-in-the-middle-vulnerability

GitRepo: https://github.com/macmule/JSS-Extension-Attributes

License: http://macmule.com/license/
"""

# Imports
import os
import subprocess
from pkg_resources import parse_version

def main():
    """
    Get a list of apps with Sparkle frameworks
    """
    # Variables
    vulnerable_apps = ''
    sparkle_info = '/Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Info.plist'
    # Use mdfind to get all apps
    get_apps = subprocess.Popen(['/usr/bin/mdfind', 'kind:app'], stdout=subprocess.PIPE,)
    # Make into a list
    app_list = get_apps.communicate()[0].splitlines()
    # For each app returned
    for app in app_list:
        # If the app has a sparkle framework
        if os.path.exists(app + sparkle_info):
            # Try to get CFBundleShortVersionString
            try:
                get_version = subprocess.Popen(['/usr/bin/defaults', 'read', app + \
         '/Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Info.plist', \
    'CFBundleShortVersionString',], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                sparkle_version = get_version.communicate()[0]
            except:
                pass
            # If the above fails, try to get the CFBundleVersion
            if not sparkle_version:
                get_version = subprocess.Popen(['/usr/bin/defaults', 'read', app + \
         '/Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Info.plist', \
              'CFBundleVersion',], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                sparkle_version = get_version.communicate()[0]
            # Try & get the SUFeedURL
            try:
                get_feed_url = subprocess.Popen(['/usr/bin/defaults', 'read', \
                                 app + '/Contents/Info.plist', 'SUFeedURL',], \
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                sparkle_feed_url = str(get_feed_url.communicate()[0])
            except:
                pass
            # If we have a SUFeedURL
            if sparkle_feed_url:
                # If Sparkle version is less than 1.13.1 & SUFeedURL is http
                if parse_version(sparkle_version) < parse_version('1.13.1') \
                            and not sparkle_feed_url.startswith('https://'):
                    # Append to string
                    vulnerable_apps = vulnerable_apps + app + '\n'
    # Run function
    vuln_apps(vulnerable_apps)


def vuln_apps(vulnerable_apps):
    """
    For EA, print list of all vulnerable apps including file paths
    """
    # If we've found any vulnerable apps
    if len(vulnerable_apps) > 0:
        # List apps in EA
        print '<result>%s</result>' % vulnerable_apps
    else:
        # If no vulnerable apps found
        print '<result>None found</result>'


if __name__ == '__main__':
    main()
