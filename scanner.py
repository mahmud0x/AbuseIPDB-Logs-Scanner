import re
import sys
import time
import ipaddress
import requests
import datetime
import flag  # pip install emoji-country-flag

# Regex for matching IPv4 addresses
ipv4_pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
private = []
public = []

def check_ip_address(ip):
    try:
        return ipaddress.ip_address(ip).is_private  # returns True/False - True = PrivateIP
    except ValueError:
        # Handle invalid IP address gracefully
        return False

def extract_ipv4_addresses(file_path):
    ipv4_addresses = []
    try:
        with open(file_path, 'r') as file:
            text = file.read()
            ipv4_addresses = re.findall(ipv4_pattern, text)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    return ipv4_addresses

if len(sys.argv) != 3:
    print("Usage: python scanner.py <full_file_path> <ABUSEDB_API_KEY>")
    sys.exit(1)

file_path = sys.argv[1]

start_time = time.time()

ipv4_addresses = extract_ipv4_addresses(file_path)

for ip in ipv4_addresses:
    # Private IP
    if check_ip_address(ip):
        private.append(ip)
    else:
        public.append(ip)

#print(set(public))
print('Private IP List:\n' + str(set(private)))


def query_abuse_ips_and_save(ip_list):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": sys.argv[2],
        "Accept": "application/json"
    }

    html_table = """
    <html>
    <head>
        <style>
            table {
                border-collapse: collapse;
                width: 100%;
            }
            th, td {
                border: 1px solid #ddd;
                text-align: left;
                padding: 8px;
            }
            th {
                background-color: #f2f2f2;
            }
        </style>
    </head>
    <body>
    <pre align="center"> 
 █████  ██████  ██    ██ ███████ ███████ ██ ██████  ██████  ██████      ██████  ███████ ███████ ██    ██ ██      ████████ ███████ 
██   ██ ██   ██ ██    ██ ██      ██      ██ ██   ██ ██   ██ ██   ██     ██   ██ ██      ██      ██    ██ ██         ██    ██      
███████ ██████  ██    ██ ███████ █████   ██ ██████  ██   ██ ██████      ██████  █████   ███████ ██    ██ ██         ██    ███████ 
██   ██ ██   ██ ██    ██      ██ ██      ██ ██      ██   ██ ██   ██     ██   ██ ██           ██ ██    ██ ██         ██         ██ 
██   ██ ██████   ██████  ███████ ███████ ██ ██      ██████  ██████      ██   ██ ███████ ███████  ██████  ███████    ██    ███████ 
                                                      by mahmud0x                      
                                                                                                                                  </pre>
    <table id="mytable">
        <tr>
            <th onclick="sortTable(0)">IP Address</th>
            <th onclick="sortTable(1)">Abuse Confidence Score</th>
            <th onclick="sortTable(2)">Country Code</th>
            <th onclick="sortTable(3)">Total Reports</th>
            <th onclick="sortTable(4)">Number of Distinct Users</th>
        </tr>
    """

    for ip in ip_list:
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": ""
        }

        try:
            # Create a session to reuse the underlying TCP connection
            session = requests.Session()

            # Send the request using the session
            response = session.get(url, headers=headers, params=params)

            if response.status_code == 200:
                data = response.json()
                # Extract specific fields
                ipAddress = data['data']['ipAddress']
                abuseConfidenceScore = int(data['data']['abuseConfidenceScore'])
                countryCode = flag.flag(data['data']['countryCode'])
                totalReports = data['data']['totalReports']
                numDistinctUsers = data['data']['numDistinctUsers']

                # Add IP information to the HTML table
                html_table += f"""
                <tr>
                    <td>{ipAddress}</td>
                    <td>{abuseConfidenceScore}</td>
                    <td>{countryCode}</td>
                    <td>{totalReports}</td>
                    <td>{numDistinctUsers}</td>
                </tr>
                """
            else:
                print(f"Request for IP {ip} failed with status code: {response.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"Error querying IP {ip}: {str(e)}")

        finally:
            if 'session' in locals() and session:
                # Close the session to release resources
                session.close()

    html_table += """
    </table>
    <script>
function sortTable(n) {
  var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
  table = document.getElementById("mytable");
  switching = true;
  // Set the sorting direction to ascending:
  dir = "asc";
  /* Make a loop that will continue until
  no switching has been done: */
  while (switching) {
    // Start by saying: no switching is done:
    switching = false;
    rows = table.rows;
    /* Loop through all table rows (except the
    first, which contains table headers): */
    for (i = 1; i < (rows.length - 1); i++) {
      // Start by saying there should be no switching:
      shouldSwitch = false;
      /* Get the two elements you want to compare,
      one from current row and one from the next: */
      x = rows[i].getElementsByTagName("TD")[n];
      y = rows[i + 1].getElementsByTagName("TD")[n];
      /* Check if the two rows should switch place,
      based on the direction, asc or desc: */
      if (dir == "asc") {
        if (n === 1) {
          // Special handling for Abuse Confidence Score (convert to integer for sorting)
          if (parseInt(x.innerHTML) > parseInt(y.innerHTML)) {
            // If so, mark as a switch and break the loop:
            shouldSwitch = true;
            break;
          }
        } else {
          if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
            // If so, mark as a switch and break the loop:
            shouldSwitch = true;
            break;
          }
        }
      } else if (dir == "desc") {
        if (n === 1) {
          // Special handling for Abuse Confidence Score (convert to integer for sorting)
          if (parseInt(x.innerHTML) < parseInt(y.innerHTML)) {
            // If so, mark as a switch and break the loop:
            shouldSwitch = true;
            break;
          }
        } else {
          if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
            // If so, mark as a switch and break the loop:
            shouldSwitch = true;
            break;
          }
        }
      }
    }
    if (shouldSwitch) {
      /* If a switch has been marked, make the switch
      and mark that a switch has been done: */
      rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
      switching = true;
      // Each time a switch is done, increase this count by 1:
      switchcount ++;
    } else {
      /* If no switching has been done AND the direction is "asc",
      set the direction to "desc" and run the while loop again. */
      if (switchcount == 0 && dir == "asc") {
        dir = "desc";
        switching = true;
      }
    }
  }
}
</script>
    </body>
    </html>
    """

    # Save HTML report
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")
    filename = f"abuse_report_{current_date}.html"
    try:
        with open(filename, "w") as file:
            file.write(html_table)
        print(f"HTML report saved as {filename}")
    except IOError as e:
        print(f"Error saving HTML report: {str(e)}")


query_abuse_ips_and_save(set(public))

end_time = time.time()
total_run_time = end_time - start_time

print(f"Total run time: {total_run_time:.2f} seconds")