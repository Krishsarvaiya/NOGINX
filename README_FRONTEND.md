# Frontend: Threat Detection Visualization

Quick instructions to run the simple Streamlit frontend for visualizing logs.

1. (Optional) Activate your project's virtual environment. Example (PowerShell):

```powershell
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned)
& .\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Run the Streamlit app:

```powershell
streamlit run app.py
```

The app will try to load `Project_Files/weblog.csv` by default. You can also upload a CSV from the sidebar.

Enhancements:
- Derived columns: `timestamp`, `method`, `endpoint`, `status_code`, `ip` are extracted when possible.
- Interactive filters: time range, status codes, IP filter, and URL substring search.
- Rich charts: Plotly charts for time series, status distribution, and top endpoints.
- Export: download filtered CSV and PNG of the time chart (requires `kaleido`).

Notes:
- If your CSV headers differ, the app attempts to map common names (e.g., `Time` -> `timestamp`, `Staus` -> `status_code`).
- Large CSVs may take time to parse; consider sampling before uploading.
 S:\Log-Analysis-Using-Machine-Learnig\.venv\Scripts\python.exe -m streamlit run src/app.py --server.headless true -server.port 8501

 S:\Log-Analysis-Using-Machine-Learnig\.venv\Scripts\python.exe src\live_analyzer.py

  python Project_Files/log_generator.py --ips 192.168.56.101 --endpoints /login,/admin --count 200 --interval 0.1 --randomize

S:\Log-Analysis-Using-Machine-Learning\.venv\Scripts\python.exe Project_Files\log_generator.py --count 10 --interval 0.1 --ips 192.168.56.112 --endpoints /signup,/seeting --randomize

python scripts/test_ws_client.py

Short summary of what to run (one-time)
1. Activate your venv (PowerShell):
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
& .\.venv\Scripts\Activate.ps1
```
2. Install deps:
```powershell
pip install -r requirements.txt
```
3. Start the Streamlit dashboard (in one terminal):
```powershell
python -m streamlit run src/app.py
```
4. Start the WebSocket live analyzer (optional, separate terminal):
```powershell
python src/live_analyzer.py
```
5. Open dashboard: http://localhost:8501  
   - In Streamlit click the sidebar `Start Live Logs` to enable live polling.
6. To simulate attacks (generator), in another terminal run:
```powershell
python Project_Files/log_generator.py --ips 192.168.56.101 --endpoints /login,/admin --count 200 --interval 0.1 --randomize
```
Expected flow and what to look for
- Live analyzer terminal: should show
  - `WebSocket server listening on ws://0.0.0.0:8765`
  - `Client connected: ('127.0.0.1', <port>)`
  - `Broadcasted stats to 1 client(s)` when it sends updates
- Streamlit dashboard (when `Start Live Logs` is ON): the Live Log Monitor counts/table update as the generator appends rows
- Browser client (live_client.html): shows raw JSON messages and the Top IPs / endpoints immediately

Why you might still see stale numbers
- You must click `Start Live Logs` in the Streamlit UI — that makes the dashboard read the file repeatedly (it bypasses the cache while live mode is on).
- If you uploaded a CSV via the sidebar, Streamlit will show that upload (not the disk file); make sure you use the disk file weblog.csv for live testing.
- If the browser client reconnects too rapidly you’ll see many connect/disconnect messages — the server still works; one persistent client is best for demos.

Quick checks to debug (run when nothing appears)
1. Confirm new rows were appended:
```powershell
Get-Content Project_Files\weblog.csv -Tail 10
```
2. Confirm live analyzer is running and broadcasting (inspect its terminal). Look for `Broadcasted stats to 1 client(s)`.
3. Confirm Streamlit live mode is ON and page not showing an uploaded file instead of the disk file.
4. If browser client shows “Disconnected”, open DevTools Console to see the WebSocket error and share it if you want help.

Safety & demo advice
- Never let teammates “attack” your real production machine. Use VMs, containers, or the log generator to simulate attacks safely.
- For a realistic demo: run the generator (or have the teammate run requests from an isolated VM using private IPs). Capture the activity in the CSV and show the dashboard reacting.
