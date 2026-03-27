

import networkx as nx
import pyreason as pr


# build a small network - 4 hosts connected together
g = nx.DiGraph()
g.add_nodes_from(["web_server", "app_server", "db_server", "workstation"])

g.add_edge("web_server", "app_server", connects_to=1)
g.add_edge("app_server", "db_server", connects_to=1)
g.add_edge("app_server", "workstation", connects_to=1)

# these hosts have known vulns
g.nodes["web_server"]["vulnerable"] = 1
g.nodes["app_server"]["vulnerable"] = 1
g.nodes["workstation"]["vulnerable"] = 1
# db_server is NOT marked vulnerable so it shouldnt get compromised

# load into pyreason
pr.settings.verbose = True
pr.settings.atom_trace = True
pr.load_graph(g)

# rule: if a compromised host connects to a vulnerable host,
# that host gets compromised 1 timestep later
pr.add_rule(pr.Rule(
    'compromised(x) <-1 compromised(y), connects_to(y,x), vulnerable(x)',
    'exploit_rule'
))

# starting condition - attacker got into the web server at t=0
pr.add_fact(pr.Fact('compromised(web_server) : [1,1]', 'initial_breach', 0, 3))

# run it
interpretation = pr.reason(timesteps=3)

# print out what got compromised and when
print("\n--- Compromised hosts by timestep ---\n")
dataframes = pr.filter_and_sort_nodes(interpretation, ['compromised'])
for t, df in enumerate(dataframes):
    if not df.empty:
        print(f"T={t}:")
        for _, row in df.iterrows():
            print(f"  {row['component']}  {row['compromised']}")
        print()


