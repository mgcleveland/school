You have been assigned topology 9906 for the PWOSPF assignment. A picture
of the assignment topology is included in the assignment description at:

  http://www.cs.arizona.edu/classes/cs525/fall09/project/assignments/r_to_r.html

The IPs assigned to your topology are as follows:

vhost1:
  eth0: 171.67.245.224 
  eth1: 171.67.245.226 
  eth2: 171.67.245.232 
vhost2:
  eth0: 171.67.245.227 
  eth1: 171.67.245.228 
  eth2: 171.67.245.236 
vhost3:
  eth0: 171.67.245.233 
  eth1: 171.67.245.234 
  eth2: 171.67.245.237 

app1: 171.67.245.229 
app2: 171.67.245.235 

You may notice that each link is assigned a 2-IP subnet (with mask 255.255.255.254).

To help you get started we have created routing table files you may use
to test your current router on the new topology.  You will need to run
three separate instances of your router.  For example:

./sr -t 9906 -v vhost1 -r rtable.vhost1
./sr -t 9906 -v vhost2 -r rtable.vhost2
./sr -t 9906 -v vhost3 -r rtable.vhost3

You will want to ensure that your current router can handle this configuration
before starting your PWOSPF implementation.  We suggest that you try and ping
each router interface and the application servers.  If your router doesn't
route the packets correctly, check that your router properly handles subnets
and next-hop entries with value 0.0.0.0.

 - Good Luck!

