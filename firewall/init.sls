{% if grains['os_family'] == 'Ubuntu' %}

ufw:
  pkg:
    - installed


turn-on-firewall:
  firewall.enable:
    - require:
      - pkg: ufw

{% endif %}