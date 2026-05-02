.PHONY: help install dev backend frontend build deploy logs test lint format clean

help:
	@echo ""
	@echo "WARDEN — Commandes disponibles"
	@echo "================================"
	@echo "make install     — Installe toutes les dépendances"
	@echo "make dev         — Lance backend + frontend en local"
	@echo "make backend     — Lance uniquement le backend (SAM local)"
	@echo "make frontend    — Lance uniquement le frontend (Vite)"
	@echo "make build       — Build Lambda + dashboard"
	@echo "make deploy      — Déploie sur AWS"
	@echo "make logs        — Stream les logs Lambda CloudWatch"
	@echo "make test        — Lance les tests Python"
	@echo "make lint        — Lint Python + TypeScript"
	@echo "make clean       — Nettoie les builds"
	@echo ""

install:
	@echo "→ Installation des dépendances Python..."
	cd backend && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
	@echo "→ Installation des dépendances Node..."
	cd dashboard && npm install
	@echo "✓ Installation terminée"

dev:
	@echo "→ Lancement en mode développement..."
	@make -j2 backend frontend

backend:
	@echo "→ Backend sur http://localhost:8000"
	@echo "→ Docs sur http://localhost:8000/docs"
	sam local start-api --port 8000 --template infrastructure/template.yaml

frontend:
	@echo "→ Frontend sur http://localhost:5173"
	cd dashboard && npm run dev

build:
	@echo "→ Build Lambda..."
	sam build --template infrastructure/template.yaml
	@echo "→ Build dashboard..."
	cd dashboard && npm run build
	@echo "✓ Build terminé"

deploy: build
	@echo "→ Déploiement sur AWS..."
	sam deploy --template infrastructure/template.yaml
	@echo "→ Déploiement dashboard..."
	cd dashboard && npm run build
	aws s3 sync dist/ s3://warden-dashboard --delete
	aws cloudfront create-invalidation \
		--distribution-id $$(aws cloudfront list-distributions \
			--query "DistributionList.Items[?Comment=='warden-dashboard'].Id" \
			--output text) \
		--paths "/*"
	@echo "✓ Déploiement terminé"

logs:
	aws logs tail /aws/lambda/warden-api --follow

test:
	cd backend && source venv/bin/activate && pytest tests/ -v

lint:
	cd backend && source venv/bin/activate && python -m ruff check app/
	cd dashboard && npm run lint

format:
	cd backend && source venv/bin/activate && python -m black app/ tests/
	cd dashboard && npm run format

clean:
	rm -rf .aws-sam/
	rm -rf backend/venv/
	rm -rf dashboard/node_modules/
	rm -rf dashboard/dist/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ Nettoyage terminé"
