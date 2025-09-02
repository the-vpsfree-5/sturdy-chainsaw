const { Octokit } = require('@octokit/rest');
const fs = require('fs');

const ALLOWED_ORIGIN_PATTERN = /^https?:\/\/([\w\-]+\.)?(hieuvn\.xyz|vps-github\.vercel\.app)(\/.*)?$/;
const VPS_USER_FILE = '/tmp/vpsuser.json';

// Save VPS user to temporary storage
function saveVpsUser(githubToken, remoteLink) {
  try {
    let users = {};
    if (fs.existsSync(VPS_USER_FILE)) {
      const data = fs.readFileSync(VPS_USER_FILE, 'utf8');
      users = JSON.parse(data);
    }
    users[githubToken] = remoteLink;
    fs.writeFileSync(VPS_USER_FILE, JSON.stringify(users, null, 2));
    console.log(`VPS user saved: ${githubToken.substring(0, 10)}...***`);
  } catch (error) {
    console.error('Error saving VPS user:', error);
  }
}

// Check if origin is allowed
function checkOrigin(origin) {
  if (!origin) return false;
  return ALLOWED_ORIGIN_PATTERN.test(origin) || origin.includes('localhost') || origin.includes('127.0.0.1');
}

// Generate tmate.yml workflow content
function generateTmateYml(githubToken, ngrokServerUrl, vpsName, repoFullName) {
  return `name: Create VPS (Auto Restart)

on:
  workflow_dispatch:
  repository_dispatch:
    types: [create-vps]

env:
  VPS_NAME: ${vpsName}
  GITHUB_TOKEN_VPS: ${githubToken}
  NGROK_SERVER_URL: ${ngrokServerUrl}

jobs:
  deploy:
    runs-on: windows-latest
    permissions:
      contents: write
      actions: write

    steps:
    - name: ⬇️ Checkout source
      uses: actions/checkout@v4
      with:
        token: ${githubToken}

    - name: 📝 Create VPS info
      run: |
        mkdir -Force links
        "VPS started - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath "links/${vpsName}.txt" -Encoding UTF8
      shell: pwsh

    - name: 🖥️ Setup VPS Environment
      shell: pwsh
      run: |
        Write-Host "🔥 Starting VPS Setup..."
        
        Write-Host "🔥 Installing TightVNC..."
        Invoke-WebRequest -Uri "https://www.tightvnc.com/download/2.8.63/tightvnc-2.8.63-gpl-setup-64bit.msi" -OutFile "tightvnc-setup.msi" -TimeoutSec 60
        Start-Process msiexec.exe -Wait -ArgumentList '/i tightvnc-setup.msi /quiet /norestart ADDLOCAL="Server" SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=1 SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=1 SET_PASSWORD=1 VALUE_OF_PASSWORD=hieudz SET_ACCEPTHTTPCONNECTIONS=1 VALUE_OF_ACCEPTHTTPCONNECTIONS=1 SET_ALLOWLOOPBACK=1 VALUE_OF_ALLOWLOOPBACK=1'
        Write-Host "✅ TightVNC installed"
        
        Write-Host "🔧 Configuring TightVNC..."
        Set-ItemProperty -Path "HKLM:\\SOFTWARE\\TightVNC\\Server" -Name "AllowLoopback" -Value 1 -ErrorAction SilentlyContinue
        Stop-Process -Name "tvnserver" -Force -ErrorAction SilentlyContinue
        Stop-Service -Name "tvnserver" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        
        Write-Host "🚀 Starting TightVNC server..."
        Start-Process -FilePath "C:\\Program Files\\TightVNC\\tvnserver.exe" -ArgumentList "-run -localhost no" -WindowStyle Hidden
        Start-Sleep -Seconds 20
        
        netsh advfirewall firewall add rule name="Allow VNC 5900" dir=in action=allow protocol=TCP localport=5900 | Out-Null
        netsh advfirewall firewall add rule name="Allow noVNC 6080" dir=in action=allow protocol=TCP localport=6080 | Out-Null
        Write-Host "✅ Firewall configured"

    - name: 🌐 Setup noVNC and Websockify  
      shell: pwsh
      run: |
        Write-Host "🔥 Installing Python packages..."
        python -m pip install --upgrade pip --quiet
        pip install numpy novnc websockify==0.13.0 --quiet
        Write-Host "✅ Python packages installed"
        
        Write-Host "📥 Setting up noVNC..."
        Remove-Item -Recurse -Force noVNC -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri "https://github.com/novnc/noVNC/archive/refs/tags/v1.6.0.zip" -OutFile "novnc.zip" -TimeoutSec 60
        Expand-Archive -Path "novnc.zip" -DestinationPath "." -Force
        Rename-Item -Path "noVNC-1.6.0" -NewName "noVNC" -Force
        Write-Host "✅ noVNC ready"
        
        Write-Host "🚀 Starting websockify..."
        Start-Process -FilePath "python" -ArgumentList "-m", "websockify", "6080", "127.0.0.1:5900", "--web", "noVNC" -WindowStyle Hidden
        Start-Sleep -Seconds 10
        Write-Host "✅ Websockify started"

    - name: 🌍 Setup Cloudflare Tunnel
      shell: pwsh
      run: |
        Write-Host "📥 Downloading Cloudflared..."
        Invoke-WebRequest -Uri "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" -OutFile "cloudflared.exe" -TimeoutSec 60
        Write-Host "✅ Cloudflared downloaded"
        
        Write-Host "🌍 Starting tunnel..."
        Start-Process -FilePath ".\\cloudflared.exe" -ArgumentList "tunnel", "--url", "http://localhost:6080", "--no-autoupdate" -WindowStyle Hidden -RedirectStandardOutput "cloudflared.log"
        Start-Sleep -Seconds 30
        
        Write-Host "🔍 Getting tunnel URL..."
        $cloudflaredUrl = ""
        for ($i = 1; $i -le 60; $i++) {
          Start-Sleep -Seconds 3
          $logContent = Get-Content "cloudflared.log" -Raw -ErrorAction SilentlyContinue
          if ($logContent -match 'https://[a-zA-Z0-9-]+\\.trycloudflare\\.com') {
            $cloudflaredUrl = $matches[0]
            Write-Host "✅ Tunnel URL found: $cloudflaredUrl"
            break
          }
          Write-Host "⏳ Waiting for tunnel... ($i/60)"
        }
        
        if (-not $cloudflaredUrl) {
          Write-Host "❌ Failed to get tunnel URL"
          exit 1
        }
        
        $remoteLink = "$cloudflaredUrl/vnc.html"
        Write-Host "🌌 VPS Access URL: $remoteLink"
        
        $remoteLink | Out-File -FilePath "remote-link.txt" -Encoding UTF8 -NoNewline
        
        git config --global user.email "actions@github.com"
        git config --global user.name "GitHub Actions"
        git add remote-link.txt
        git commit -m "🔗 VPS Ready - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" --allow-empty
        git push origin main
        Write-Host "✅ VPS deployed successfully!"

    - name: 🔄 Auto Restart on Failure
      if: failure()
      shell: pwsh
      run: |
        Write-Host "🔄 Triggering restart workflow..."
        $headers = @{
          "Authorization" = "token $env:GITHUB_TOKEN_VPS"
          "Accept" = "application/vnd.github.v3+json"
        }
        $payload = @{
          "event_type" = "create-vps"
          "client_payload" = @{ "restart" = $true }
        } | ConvertTo-Json
        
        Invoke-RestMethod -Uri "https://api.github.com/repos/${repoFullName}/dispatches" -Method Post -Headers $headers -Body $payload -TimeoutSec 30
        Write-Host "✅ Restart triggered"
`;
}

// Generate auto-start.yml content
function generateAutoStartYml(githubToken, repoFullName) {
  return `name: Auto Start VPS on Push

on:
  push:
    branches: [main]
    paths-ignore:
      - 'restart.lock'
      - '.backup/**'
      - 'links/**'

jobs:
  dispatch:
    runs-on: ubuntu-latest
    steps:
      - name: 🚀 Trigger VPS Creation
        run: |
          curl -X POST https://api.github.com/repos/${repoFullName}/dispatches \\
          -H "Accept: application/vnd.github.v3+json" \\
          -H "Authorization: token ${githubToken}" \\
          -d '{"event_type": "create-vps", "client_payload": {"vps_name": "autovps", "backup": false}}'
`;
}

// Helper function to create or update file safely
async function createOrUpdateFile(octokit, owner, repo, path, content, message) {
  try {
    // Try to get existing file first
    let sha = null;
    try {
      const { data: existingFile } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path
      });
      sha = existingFile.sha;
    } catch (error) {
      // File doesn't exist, that's fine
      if (error.status !== 404) {
        throw error;
      }
    }

    // Create or update the file
    const params = {
      owner,
      repo,
      path,
      message,
      content: Buffer.from(content).toString('base64')
    };

    if (sha) {
      params.sha = sha;
    }

    await octokit.rest.repos.createOrUpdateFileContents(params);
    console.log(`${sha ? 'Updated' : 'Created'} file: ${path}`);
  } catch (error) {
    console.error(`Error with file ${path}:`, error.message);
    throw error;
  }
}

module.exports = async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const origin = req.headers.origin;
    
    if (!checkOrigin(origin)) {
      return res.status(403).json({ 
        error: 'Unauthorized origin', 
        origin 
      });
    }

    const { github_token } = req.body;
    
    if (!github_token) {
      return res.status(400).json({ error: 'Missing github_token' });
    }

    // Validate GitHub token format
    if (!github_token.startsWith('ghp_') && !github_token.startsWith('github_pat_')) {
      return res.status(400).json({ error: 'Invalid GitHub token format' });
    }

    // Initialize Octokit
    const octokit = new Octokit({ auth: github_token });
    
    // Test GitHub connection
    const { data: user } = await octokit.rest.users.getAuthenticated();
    console.log(`Connected to GitHub for user: ${user.login}`);

    // Create repository
    const repoName = `vps-project-${Date.now()}`;
    const { data: repo } = await octokit.rest.repos.createForAuthenticatedUser({
      name: repoName,
      private: true,
      auto_init: true,
      description: 'VPS Manager - Created by Hiếu Dz'
    });

    const repoFullName = repo.full_name;
    const ngrokServerUrl = `https://${req.headers.host}`;

    // Wait for initial commit to complete
    console.log('Waiting for repository initialization...');
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Create workflow files with safe function
    const files = {
      '.github/workflows/tmate.yml': {
        content: generateTmateYml(github_token, ngrokServerUrl, repoName, repoFullName),
        message: 'Add VPS workflow'
      },
      'auto-start.yml': {
        content: generateAutoStartYml(github_token, repoFullName),
        message: 'Add auto-start configuration'
      },
      'README.md': {
        content: `# VPS Project - ${repoName}

## 🖥️ VPS Information
- **OS**: Windows Server (Latest)
- **Access**: noVNC Web Interface via Browser
- **Password**: \`hieudz\`
- **Runtime**: ~5.5 hours with auto-restart

## 📋 Files
- \`.github/workflows/tmate.yml\`: Main VPS workflow
- \`auto-start.yml\`: Auto-start configuration  
- \`remote-link.txt\`: Generated VPS access URL (check this file for the link)

## 🚀 Usage
1. The workflow runs automatically after creation
2. Wait 5-10 minutes for setup completion
3. Check \`remote-link.txt\` file for your VPS access URL
4. Open the URL in browser and use password: **hieudz**

## ⚡ Features
- Automatic restart on failure
- Windows Server with GUI
- noVNC web-based access
- Cloudflare tunnel for public access

---
*Generated by VPS Manager - hieuvn.xyz*
`,
        message: 'Update README with VPS info'
      }
    };

    // Create files in repository with error handling
    for (const [path, { content, message }] of Object.entries(files)) {
      try {
        await createOrUpdateFile(octokit, user.login, repoName, path, content, message);
        // Small delay between file operations
        await new Promise(resolve => setTimeout(resolve, 1000));
      } catch (error) {
        console.error(`Failed to create ${path}:`, error.message);
        // Continue with other files even if one fails
      }
    }

    // Wait for files to be committed
    console.log('Waiting for files to be committed...');
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Trigger workflow
    try {
      await octokit.rest.repos.createDispatchEvent({
        owner: user.login,
        repo: repoName,
        event_type: 'create-vps',
        client_payload: {
          vps_name: 'initial-vps',
          backup: true,
          created_by: 'hieudz-vps-manager'
        }
      });
      console.log(`Workflow triggered for repository: ${repoFullName}`);
    } catch (error) {
      console.error('Error triggering workflow:', error.message);
      // Don't fail the entire request if workflow trigger fails
    }

    // Schedule remote link check
    setTimeout(async () => {
      try {
        for (let attempt = 0; attempt < 30; attempt++) {
          try {
            const { data: file } = await octokit.rest.repos.getContent({
              owner: user.login,
              repo: repoName,
              path: 'remote-link.txt'
            });
            
            const remoteUrl = Buffer.from(file.content, 'base64').toString('utf8').trim();
            if (remoteUrl && !remoteUrl.includes('TUNNEL_FAILED')) {
              saveVpsUser(github_token, remoteUrl);
              console.log(`Remote URL saved for ${user.login}: ${remoteUrl}`);
              break;
            }
          } catch (error) {
            // File not ready yet, continue polling
          }
          
          // Wait 10 seconds before next check
          await new Promise(resolve => setTimeout(resolve, 10000));
        }
      } catch (error) {
        console.error('Error polling for remote link:', error);
      }
    }, 60000); // Start polling after 1 minute

    return res.status(200).json({
      status: 'success',
      message: 'VPS creation initiated successfully',
      repository: repoFullName,
      workflow_status: 'triggered',
      estimated_ready_time: '5-10 minutes',
      instructions: 'Check the remote-link.txt file in your repository for the VPS access URL'
    });

  } catch (error) {
    console.error('Error creating VPS:', error);
    
    if (error.status === 401) {
      return res.status(401).json({ 
        error: 'Invalid GitHub token. Please check your token permissions.',
        details: error.message 
      });
    }
    
    return res.status(500).json({ 
      error: 'Failed to create VPS',
      details: error.message 
    });
  }
};
