Digital Ocean API Python Wrapper
================================

Inspired by [ahmontero/dop](https://github.com/ahmontero/dop).

Installation
============

```bash
pip install dopy
``

Getting Started
===============

To interact with Digital Ocean, you first need .. a digital ocean account with 
valid API keys. 

Keys can be set either as env variables or within the code.

```bash
    $ export DO_API_TOKEN='api_token'
```

```pycon
    >>> from dopy.manager import DoManager
    >>> do = DoManager('api_token')
```

Methods
=======

The methods of the DoManager are self explanatory, for example:

```pycon
    >>> do.all_active_droplets()
    >>> do.show_droplet('12345')
    >>> do.destroy_droplet('12345')
    >>> do.all_regions()
    >>> do.all_images()
    >>> do.all_ssh_keys()
    >>> do.sizes()
    >>> do.all_domains()
    >>> do.show_domain('exapmle.com')
    >>> do.new_droplet('new_droplet', '512mb', 'lamp', 'ams2')
```

Methods for Floating IPs are:

```pycon
    >>> do.all_floating_ips()
    >>> do.new_floating_ip(droplet_id, region)
    >>> do.destroy_floating_ip(ip_addr)
    >>> do.assign_floating_ip(ip_addr)
    >>> do.unassign_floating_ip(ip_addr)
    >>> do.list_floating_ip_actions(ip_addr)
    >>> do.get_floating_ip_action(ip_addr, action_id)
```

TODO
====

See github issue list - post if any needed

https://github.com/devo-ps/dopy/issues
