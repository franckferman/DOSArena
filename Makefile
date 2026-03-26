# DOSArena — Master Makefile
#
# QUICK START:
#   make up        Start everything (lab + judge)
#   make shell     Open attacker bash
#   make monitor   Open monitor bash
#   make status    Show all IPs and services
#   make down      Stop everything
#
# TERRAFORM AWS:
#   make tf-init   Init providers
#   make tf-apply  Deploy cloud lab
#   make tf-destroy Tear down

export COMPOSE_BAKE := false
COMPOSE = docker compose -f docker/docker-compose.yml
TF_DIR  = terraform/aws

.PHONY: up down shell monitor status clean tf-init tf-apply tf-destroy

up:
	@echo "[*] Starting DOSArena..."
	$(COMPOSE) up -d --build
	@echo "[*] Disabling rp_filter on bridge interfaces (required for SYN flood spoofing)..."
	@sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
	@sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
	@for iface in $$(ls /proc/sys/net/ipv4/conf/); do \
		sysctl -w net.ipv4.conf.$${iface}.rp_filter=0 >/dev/null 2>&1 || true; \
	done
	@echo ""
	@echo "[+] DOSArena online."
	@echo "    make shell     -> attacker node"
	@echo "    make monitor   -> traffic monitoring"
	@echo "    make status    -> full IP/service overview"
	@echo ""
	@echo "    Judge API:   http://localhost:8888"
	@echo "    Grafana:     http://localhost:3000  (admin/dosarena)"
	@echo "    Prometheus:  http://localhost:9090"

down:
	$(COMPOSE) down

shell:
	$(COMPOSE) exec attacker bash

monitor:
	$(COMPOSE) exec monitor bash

status:
	@echo ""
	@echo "DOSArena — Service Map"
	@echo "══════════════════════════════════════════════════════"
	@$(COMPOSE) ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || true
	@echo ""
	@echo "Network:"
	@echo "  10.0.1.10   attacker"
	@echo ""
	@echo "  [DMZ — Vulnerable Targets]"
	@echo "  10.0.2.20   apache-vuln      HTTP:80   Slowloris/SYN/SlowPOST"
	@echo "  10.0.2.30   dns-open         UDP:53    DNS amp ~60x"
	@echo "  10.0.2.31   ntp-vuln         UDP:123   NTP amp ~550x"
	@echo "  10.0.2.32   snmp-vuln        UDP:161   SNMP amp ~650x"
	@echo "  10.0.2.40   mysql-vuln       TCP:3306  max_conn=50"
	@echo "  10.0.2.50   fw-stateless     HTTP:80   ACK/XMAS bypass"
	@echo "  10.0.2.51   fw-stateful      HTTP:80   conntrack table limited"
	@echo ""
	@echo "  [Protected Targets]"
	@echo "  10.0.3.20   apache-protected HTTP:80   hardened"
	@echo "  10.0.3.21   nginx-protected  HTTP:80   hardened"
	@echo ""
	@echo "  [Management]"
	@echo "  10.0.99.30  judge            :8888     DOSArena Judge API"
	@echo "  10.0.99.20  prometheus       :9090"
	@echo "  10.0.99.21  grafana          :3000"
	@echo ""
	@echo "Scenarios:"
	@curl -s http://localhost:8888/status 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "  (judge not reachable — run 'make up' first)"

logs:
	$(COMPOSE) logs -f

clean:
	$(COMPOSE) down -v --rmi local
	docker image prune -f

tf-init:
	cd $(TF_DIR) && terraform init

tf-plan:
	cd $(TF_DIR) && terraform plan

tf-apply:
	cd $(TF_DIR) && terraform apply
	@cd $(TF_DIR) && terraform output ssh_command

tf-destroy:
	@echo "[!] Destroying AWS infrastructure in 5s... Ctrl+C to cancel"
	@sleep 5
	cd $(TF_DIR) && terraform destroy
