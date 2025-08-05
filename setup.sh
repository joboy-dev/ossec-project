#!/bin/bash

# === CONFIGURATION ===
REPO_URL="https://github.com/joboy-dev/ossec-project.git"
INSTALL_DIR="/opt/ossec-dashboard"

echo "🚀 Setting up OSSEC Dashboard..."

# === 1️⃣ Clone or update repository ===
if [ -d "$INSTALL_DIR" ]; then
    echo "🔄 Updating existing project in $INSTALL_DIR..."
    sudo git -C "$INSTALL_DIR" pull
else
    echo "📥 Cloning repository into $INSTALL_DIR..."
    sudo git clone "$REPO_URL" "$INSTALL_DIR"
fi

# === 2️⃣ Set permissions ===
sudo chown -R $USER:$USER "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/scripts/sync_ossec_alerts.sh"

echo "Setting up ossec-dashboard..."
cd "$INSTALL_DIR"

# === 3️⃣ Create .env file ===
echo "🔄 Creating .env file..."
cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"

if [ -d "env" ]; then
    echo "🔎 Virtual environment already exists. Skipping creation."
else
    echo "🔄 Creating virtual environment..."
    python3 -m venv env
fi

echo "🔄 Activating virtual environment..."
source env/bin/activate

echo "🔄 Installing dependencies..."
pip install -r requirements.txt

echo "🔄 Making start.sh executable..."
chmod +x start.sh

# === 3️⃣ Add cron job (run every minute) ===
(crontab -l 2>/dev/null | grep -v "$INSTALL_DIR/scripts/sync_ossec_alerts.sh" ; echo "* * * * * /bin/bash $INSTALL_DIR/scripts/sync_ossec_alerts.sh >> /tmp/ossec_cron.log 2>&1") | crontab -

echo "✅ ossec-dashboard setup complete!"
echo "📂 Installed in: $INSTALL_DIR"
echo "🕒 Cron job added (runs every minute). Check logs: tail -f /tmp/ossec_cron.log"

echo "🔄 Starting ossec-dashboard..."
./start.sh

echo "Done!"
