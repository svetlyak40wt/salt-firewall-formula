import copy
import re
import os.path
import logging
import socket
import itertools


_STATUS_LINE_RE = re.compile('^(\d+).*ALLOW IN[ ]+([^ ]*)$')

log = logging.getLogger('salt.state.ufw')


class ThereWereWarnings(RuntimeError): pass


def _check_warnings_and_raise_error(result):
    warnings = [line
             for line in result['stderr'].split('\n')
             if line.startswith('WARN: ')]
    if warnings:
        raise ThereWereWarnings(*warnings)


def _resolve(host):
    return socket.gethostbyname(host)


def _expand_host_or_group(name, groups):
    if isinstance(name, basestring):
        names = [name]
    else:
        names = name
    
    for name in names:
        if name.startswith('$'):
            name = name[1:]

            if name not in groups:
                raise RuntimeError('Group ${0} not found in pillars.'.format(name))

            for host in groups[name]:
                yield host
        else:
            yield name


def _expand_groups(rules, groups):
    rules = copy.deepcopy(rules)
    groups_in_rules = [key for key in rules.keys() if key.startswith('$')]
    
    for group in groups_in_rules:
        group_rules = rules[group]
        for host in _expand_host_or_group(group, groups):
            rules.setdefault(host, [])
            rules[host].extend(group_rules)
        del rules[group]
        
    return rules



def _expand_rule(rule, groups):
    """Returns separate rules, for each host in 'from' key.
    Also, it resolves hosts to ips and expands groups"""
    
    if 'from' in rule:
        hosts = _expand_host_or_group(rule['from'], groups)

        return [{'port': rule['port'], 'from': _resolve(host)}
                for host in hosts]

    return [rule]


def _create_command(rule, policy='allow'):
    """Creates one or more command to enable rule."""
    if 'from' in rule:
        text = 'ufw {policy} from {from} to any port {port}'
    else:
        text = 'ufw {policy} {port}'

    return text.format(policy=policy, **rule)


def _parse_ufw_status(text):
    lines = text.splitlines()
    lines = itertools.dropwhile(lambda line: not line.startswith('-- '), lines)
    # skip divider
    lines.next()
    rules = []
    skipped_lines = []
    
    for line in lines:
        match = _STATUS_LINE_RE.match(line)
        if match is None:
            # we'll ignore ipv6 lines because they are just duplicate
            # ipv4 rules
            if '(v6)' not in line:
                skipped_lines.append(line)
        else:
            rule = dict(port=int(match.group(1)))
            ip = match.group(2)
            if ip != 'Anywhere':
                rule['from'] = ip
            rules.append(rule)
            
    return rules, skipped_lines


def enable(name, ports=[]):
    comments = []
    changes = {}

    status = __salt__['cmd.run_stdout']('ufw status verbose')
    current_rules, skipped_lines = _parse_ufw_status(status)
    if skipped_lines:
        comments.append('These lines were skipped during processing current state:\n' +
                        '\n'.join(skipped_lines))
    

    rules = __salt__['pillar.get']('firewall:rules')
    groups = __salt__['pillar.get']('firewall:groups')
    my_host = socket.gethostname()

    rules = _expand_groups(rules, groups)

    rules = rules.get(my_host)
    state_rules = list(itertools.chain(*[_expand_rule(rule, groups) for rule in rules]))

    add_commands = [(_create_command(rule, 'allow'), rule)
                    for rule in state_rules
                    if rule not in current_rules]
    delete_commands = [(_create_command(rule, 'delete allow'), rule)
                       for rule in current_rules
                       if rule not in state_rules]

    for command, rule in add_commands:
        result = __salt__['cmd.run_all'](command)
        _check_warnings_and_raise_error(result)
        changes[repr(rule)] = 'Added'

    for command, rule in delete_commands:
        result = __salt__['cmd.run_all'](command)
        _check_warnings_and_raise_error(result)        
        changes[repr(rule)] = 'Removed'
        
    return dict(name=name,
                changes=changes,
                result=True,
                comment='\n'.join(comments))

