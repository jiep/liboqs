#!/usr/bin/env python3

# SPDX-License-Identifier: MIT

import argparse
import os
import subprocess
import yaml
import inspect

parser = argparse.ArgumentParser()
parser.add_argument("--liboqs-root", default=os.path.join("..", ".."))
parser.add_argument("-w", "--write-changes", dest="write_changes", action='store_true')
parser.add_argument("-v", "--verbosity", type=int)
args = parser.parse_args()

if args.verbosity:
    DEBUG = args.verbosity
else:
    DEBUG = 0

if not args.write_changes:
    print("--write-changes not set; changes will not be written out.")

def shell(command, expect=0):
    subprocess_stdout = None if DEBUG > 0 else subprocess.DEVNULL
    ret = subprocess.run(command, stdout=subprocess_stdout, stderr=subprocess_stdout)
    if ret.returncode != expect:
        raise Exception("'{}' failed with error {}. Expected {}.".format(" ".join(command), ret, expect))

def load_yaml(filename, encoding='utf-8'):
    with open(filename, mode='r', encoding=encoding) as fh:
        return yaml.safe_load(fh.read())

def store_yaml(filename, contents, encoding='utf-8'):
    with open(filename, mode='w', encoding=encoding) as fh:
        yaml.dump(contents, fh, sort_keys=False, allow_unicode=True)

def fetch_upstream(upstream_info):
    work_dir_root = os.path.join(args.liboqs_root, 'scripts', 'copy_from_upstream', 'repos')
    os.makedirs(work_dir_root, exist_ok=True)

    work_dir = os.path.join(work_dir_root, upstream_info['name'])
    work_dotgit = os.path.join(work_dir, '.git')
    if not os.path.exists(work_dotgit):
        shell(['git', 'init', work_dir])
        shell(['git', '--git-dir', work_dotgit, 'remote', 'add', 'origin', upstream_info['git_url']])
        shell(['git', '--git-dir', work_dotgit, '--work-tree', work_dir, 'remote', 'set-url', 'origin', upstream_info['git_url']])
        shell(['git', '--git-dir', work_dotgit, '--work-tree', work_dir, 'fetch', '--depth=1', 'origin', upstream_info['git_commit']])
        shell(['git', '--git-dir', work_dotgit, '--work-tree', work_dir, 'reset', '--hard', upstream_info['git_commit']])

    return work_dir

def rhs_if_not_equal(lhs, rhs, not_equal_msg):
    if lhs != rhs:
        if DEBUG > 0:
            caller = inspect.getframeinfo(inspect.stack()[1][0])
            print("Line {}: Discrepancy in {}: lhs: {}, rhs: {}".format(caller.lineno, not_equal_msg, lhs, rhs))
            if DEBUG > 1:
               exit(1)
        return rhs
    return lhs

def get_upstream_info(upstream_list, location):
    for i in upstream_list:
       if i['name'] == location:
           return i
    print("Error: Cannot find location %s in upstream list" % (location))
    print(upstream_list)
    exit(1)

def get_oqs_yaml(param_list, name):
    ctr=0
    for i in param_list:
       if i['name'] == name:
           return ctr, i
       ctr=ctr+1
    print("Error: Cannot find name %s in param list" % (name))
    print(param_list)
    exit(1)

# Merge documentation contained in args.liboqs_root/docs/algorithms/kem/kem['name'].yml with upstream information:
# Args: 
# kems: List of kems in copy_from_upstream.yml
# upstream_info: Hashtable of upstream information (keyed by upstream source)
#  incl. entry: 'upstream_root' pointing to local folder containing source code 
def update_upstream_kem_alg_docs(kems, upstream_info):
    for kem in kems:
        ui = get_upstream_info(upstream_info, kem['upstream_location'])
        upstream_root = ui['upstream_root']
        meta_yaml_path_template = ui['kem_meta_path']
        if DEBUG > 1:
            print("Working on KEM %s using path %s and META file %s" % (kem, upstream_root, meta_yaml_path_template))
        if True: # for all upstream sources:
            oqs_yaml_path = os.path.join(args.liboqs_root, 'docs', 'algorithms', 'kem', '{}.yml'.format(kem['name']))
            if os.path.isfile(oqs_yaml_path):
               oqs_yaml = load_yaml(oqs_yaml_path)
            else:
                continue

            # We cannot assume that the ordering of "parameter-sets"
            # in the OQS YAML files matches that of copy_from_upstream.yml
            # hence use helper function get_oqs_yaml(alg_name)
            for scheme in kem['schemes']:
                upstream_meta_path = os.path.join(upstream_root, meta_yaml_path_template.format_map(scheme))
                if DEBUG > 0:
                    print("Examining {}'s META.yml.".format(scheme['pretty_name_full']))
                upstream_yaml = load_yaml(upstream_meta_path)

                oqs_yaml['type'] = rhs_if_not_equal(oqs_yaml['type'], upstream_yaml['type'], "type")
                oqs_yaml['principal-submitters'] = rhs_if_not_equal(oqs_yaml['principal-submitters'], upstream_yaml['principal-submitters'], "principal-submitters")

                upstream_base_url = ui['git_url'][:-len(".git")]
                oqs_yaml['upstream'] = rhs_if_not_equal("{}/commit/{}".format(upstream_base_url, ui['git_commit']), oqs_yaml['upstream'], "upstream")

                if 'auxiliary-submitters' in upstream_yaml:
                        oqs_yaml['auxiliary-submitters'] = rhs_if_not_equal(oqs_yaml['auxiliary-submitters'] if 'auxiliary-submitters' in oqs_yaml else '', upstream_yaml['auxiliary-submitters'], "auxiliary-submitters")

                index, oqs_scheme_yaml = get_oqs_yaml(oqs_yaml['parameter-sets'], scheme['pretty_name_full'])

                # TODO: PQClean and liboqs pretty-naming conventions for the
                # following algorithms are out of sync.
                if kem['name'] == 'classic_mceliece' or kem['name'] == 'hqc' or kem['name'] == 'ntru' or kem['name'] == 'saber':
                    oqs_scheme_yaml['name'] = rhs_if_not_equal(oqs_scheme_yaml['name'], scheme['pretty_name_full'], "scheme pretty name")
                else:
                    oqs_scheme_yaml['name'] = rhs_if_not_equal(oqs_scheme_yaml['name'], upstream_yaml['name'], "scheme pretty name")

                oqs_scheme_yaml['claimed-nist-level'] = rhs_if_not_equal(oqs_scheme_yaml['claimed-nist-level'], upstream_yaml['claimed-nist-level'], "claimed-nist-level")
                oqs_scheme_yaml['claimed-security'] = rhs_if_not_equal(oqs_scheme_yaml['claimed-security'], upstream_yaml['claimed-security'], "claimed-security")
                oqs_scheme_yaml['length-public-key'] = rhs_if_not_equal(oqs_scheme_yaml['length-public-key'], upstream_yaml['length-public-key'], "length-public-key")
                oqs_scheme_yaml['length-ciphertext'] = rhs_if_not_equal(oqs_scheme_yaml['length-ciphertext'], upstream_yaml['length-ciphertext'], "length-ciphertext")
                oqs_scheme_yaml['length-secret-key'] = rhs_if_not_equal(oqs_scheme_yaml['length-secret-key'], upstream_yaml['length-secret-key'], "legnth-secret-key")
                oqs_scheme_yaml['length-shared-secret'] = rhs_if_not_equal(oqs_scheme_yaml['length-shared-secret'], upstream_yaml['length-shared-secret'], "length-shared-secret")

                for impl_index, impl in enumerate(oqs_scheme_yaml['implementations']):
                    for pqclean_impl in upstream_yaml['implementations']:
                        if impl['upstream-id'] == pqclean_impl['name']:
                            break

                    if 'supported_platforms' in pqclean_impl:
                        impl['supported-platforms'] = rhs_if_not_equal(impl['supported-platforms'], pqclean_impl['supported_platforms'], "supported-platforms")
                    else:
                        impl['supported-platforms'] = rhs_if_not_equal(impl['supported-platforms'], "all", "supported-platforms")

                    # Logic to add Common_META.yml components
                    uir = get_upstream_info(upstream_yaml['implementations'], impl['upstream-id'])
                    if (uir != None) and ('common_dep' in uir):
                        upstream_common_path = upstream_meta_path.replace(scheme['pretty_name_full'], "Common")
                        upstream_common_yaml = load_yaml(upstream_common_path)
                        for c in uir['common_dep'].split(' '):
                            ur = get_upstream_info(upstream_common_yaml['commons'], c)
                            if (ur != None) and ('supported_platforms' in ur):
                               if 'required_flags' in ur['supported_platforms'][0].keys():
                                  impl['supported-platforms'][0]['required_flags']=list(set(impl['supported-platforms'][0]['required_flags']+ur['supported_platforms'][0]['required_flags']))

                    oqs_scheme_yaml['implementations'][impl_index] = impl

                oqs_yaml['parameter-sets'][index] = oqs_scheme_yaml

            if args.write_changes:
                store_yaml(oqs_yaml_path, oqs_yaml)

def update_upstream_sig_alg_docs(sigs, upstream_info):
    for sig in sigs:
        ui = get_upstream_info(upstream_info, sig['upstream_location'])
        upstream_root = ui['upstream_root']
        meta_yaml_path_template = ui['sig_meta_path']
        if DEBUG > 1:
            print("Working on SIG %s using path %s and META file %s" % (sig, upstream_root, meta_yaml_path_template))
        if True: # for all upstream sources:
            oqs_yaml_path = os.path.join(args.liboqs_root, 'docs', 'algorithms', 'sig', '{}.yml'.format(sig['name']))
            if os.path.isfile(oqs_yaml_path):
               oqs_yaml = load_yaml(oqs_yaml_path)
            else:
                continue

            # We assume that the ordering of "parameter-sets"
            # in the OQS YAML files matches that of copy_from_upstream.yml
            for scheme in sig['schemes']:
                if DEBUG > 0:
                    print("Examining {}'s META.yml.".format(scheme['pretty_name_full']))
                upstream_meta_path = os.path.join(upstream_root, meta_yaml_path_template.format_map(scheme))
                upstream_yaml = load_yaml(upstream_meta_path)

                oqs_yaml['type'] = rhs_if_not_equal(oqs_yaml['type'], upstream_yaml['type'], "type")
                oqs_yaml['principal-submitters'] = rhs_if_not_equal(oqs_yaml['principal-submitters'], upstream_yaml['principal-submitters'], "principal-submitters")

                upstream_base_url = ui['git_url'][:-len(".git")]
                oqs_yaml['upstream'] = rhs_if_not_equal("{}/commit/{}".format(upstream_base_url, ui['git_commit']), oqs_yaml['upstream'], "upstream")

                if 'auxiliary-submitters' in upstream_yaml:
                        oqs_yaml['auxiliary-submitters'] = rhs_if_not_equal(oqs_yaml['auxiliary-submitters'] if 'auxiliary-submitters' in oqs_yaml else '', upstream_yaml['auxiliary-submitters'], "auxiliary-submitters")

                index, oqs_scheme_yaml = get_oqs_yaml(oqs_yaml['parameter-sets'], scheme['pretty_name_full'])

                # TODO: PQClean and liboqs pretty-naming conventions for the
                # following algorithms are out of sync.
                if sig['name'] == 'sphincs' or sig['name'] == 'rainbow':
                    oqs_scheme_yaml['name'] = rhs_if_not_equal(oqs_scheme_yaml['name'], scheme['pretty_name_full'], "scheme pretty name")
                else:
                    oqs_scheme_yaml['name'] = rhs_if_not_equal(oqs_scheme_yaml['name'], upstream_yaml['name'], "scheme pretty name")

                oqs_scheme_yaml['claimed-nist-level'] = rhs_if_not_equal(oqs_scheme_yaml['claimed-nist-level'], upstream_yaml['claimed-nist-level'], "claimed-nist-level")
                oqs_scheme_yaml['claimed-security'] = rhs_if_not_equal(oqs_scheme_yaml['claimed-security'], 'EUF-CMA', "claimed-security")
                oqs_scheme_yaml['length-public-key'] = rhs_if_not_equal(oqs_scheme_yaml['length-public-key'], upstream_yaml['length-public-key'], "length-public-key")
                oqs_scheme_yaml['length-secret-key'] = rhs_if_not_equal(oqs_scheme_yaml['length-secret-key'], upstream_yaml['length-secret-key'], "legnth-secret-key")
                oqs_scheme_yaml['length-signature'] = rhs_if_not_equal(oqs_scheme_yaml['length-signature'], upstream_yaml['length-signature'], "length-signature")

                for impl_index, impl in enumerate(oqs_scheme_yaml['implementations']):
                    for pqclean_impl in upstream_yaml['implementations']:
                        if impl['upstream-id'] == pqclean_impl['name']:
                            break

                    if 'supported_platforms' in pqclean_impl:
                        impl['supported-platforms'] = rhs_if_not_equal(impl['supported-platforms'], pqclean_impl['supported_platforms'], "supported-platforms")
                    else:
                        impl['supported-platforms'] = rhs_if_not_equal(impl['supported-platforms'], "all", "supported-platforms")

                    # Logic to add Common_META.yml components
                    uir = get_upstream_info(upstream_yaml['implementations'], impl['upstream-id'])
                    if (uir != None) and ('common_dep' in uir):
                        upstream_common_path = upstream_meta_path.replace(scheme['pretty_name_full'], "Common")
                        upstream_common_yaml = load_yaml(upstream_common_path)
                        for c in uir['common_dep'].split(' '):
                            ur = get_upstream_info(upstream_common_yaml['commons'], c)
                            if (ur != None) and ('supported_platforms' in ur):
                               if 'required_flags' in ur['supported_platforms'][0].keys():
                                  impl['supported-platforms'][0]['required_flags']=list(set(impl['supported-platforms'][0]['required_flags']+ur['supported_platforms'][0]['required_flags']))

                    oqs_scheme_yaml['implementations'][impl_index] = impl

                oqs_yaml['parameter-sets'][index] = oqs_scheme_yaml

            if args.write_changes:
                store_yaml(oqs_yaml_path, oqs_yaml)

instructions = load_yaml(
    os.path.join(args.liboqs_root, 'scripts', 'copy_from_upstream', 'copy_from_upstream.yml'),
    encoding='utf-8')

for upstream in instructions['upstreams']:
  if 'git_url' in upstream.keys():
    upstream['upstream_root'] = fetch_upstream(upstream)

update_upstream_kem_alg_docs(instructions['kems'], instructions['upstreams'])
update_upstream_sig_alg_docs(instructions['sigs'], instructions['upstreams'])
