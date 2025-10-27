import sys
import os
import subprocess
import threading
import webbrowser
import time
from datetime import datetime
from PIL import Image, ImageDraw
import tkinter as tk
from tkinter import messagebox
import json

try:
    import pystray
except ImportError:
    print("pystray not installed. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pystray"])
    import pystray

class AgentTrayUI:
    def __init__(self):
        self.agent_process = None
        self.agent_running = False
        self.icon = None
        self.status_data = {
            'last_scan': 'Never',
            'threats_found': 0,
            'status': 'Stopped'
        }
        
    def create_icon(self, color):
        """Create a simple colored dot icon"""
        try:
            image = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
            draw = ImageDraw.Draw(image)
            
            if color == 'green':
                fill_color = (0, 255, 0, 255)
            else:
                fill_color = (255, 0, 0, 255)
                
            draw.ellipse([16, 16, 48, 48], fill=fill_color, outline=(0, 0, 0, 255), width=2)
            return image
        except Exception as e:
            print(f"Error creating icon: {e}")
            # Fallback to minimal icon
            image = Image.new('RGBA', (16, 16), (128, 128, 128, 255))
            return image
    
    def update_icon(self):
        """Update the tray icon based on agent status"""
        try:
            if self.icon:
                color = 'green' if self.agent_running else 'red'
                self.icon.icon = self.create_icon(color)
        except Exception as e:
            print(f"Error updating icon: {e}")
    
    def start_agent(self, icon=None, item=None):
        """Start the agent as a subprocess"""
        try:
            if not self.agent_running:
                agent_path = os.path.join(os.path.dirname(__file__), 'agent.py')
                if os.path.exists(agent_path):
                    self.agent_process = subprocess.Popen([sys.executable, agent_path])
                    self.agent_running = True
                    self.status_data['status'] = 'Running'
                    self.status_data['last_scan'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    self.update_icon()
                    print("Agent started")
                else:
                    self.show_error("Agent file not found")
        except Exception as e:
            print(f"Error starting agent: {e}")
            self.show_error(f"Failed to start agent: {str(e)}")
    
    def stop_agent(self, icon=None, item=None):
        """Stop the agent subprocess"""
        try:
            if self.agent_running and self.agent_process:
                self.agent_process.terminate()
                self.agent_process.wait(timeout=5)
                self.agent_running = False
                self.status_data['status'] = 'Stopped'
                self.update_icon()
                print("Agent stopped")
        except subprocess.TimeoutExpired:
            try:
                self.agent_process.kill()
                self.agent_running = False
                self.status_data['status'] = 'Stopped'
                self.update_icon()
            except Exception as e:
                print(f"Error killing agent process: {e}")
        except Exception as e:
            print(f"Error stopping agent: {e}")
    
    def view_status(self, icon=None, item=None):
        """Show status popup using tkinter"""
        try:
            def show_status():
                root = tk.Tk()
                root.withdraw()
                
                status_text = f"""Agent Status: {self.status_data['status']}
Last Scan: {self.status_data['last_scan']}
Threats Found: {self.status_data['threats_found']}
Process Running: {self.agent_running}"""
                
                messagebox.showinfo("CyberSec Agent Status", status_text)
                root.destroy()
            
            threading.Thread(target=show_status, daemon=True).start()
        except Exception as e:
            print(f"Error showing status: {e}")
    
    def open_dashboard(self, icon=None, item=None):
        """Open the web dashboard in default browser"""
        try:
            webbrowser.open('https://cybersec-suite.vercel.app/dashboard')
        except Exception as e:
            print(f"Error opening dashboard: {e}")
            self.show_error(f"Failed to open dashboard: {str(e)}")
    
    def show_error(self, message):
        """Show error message using tkinter"""
        try:
            def show_error_popup():
                root = tk.Tk()
                root.withdraw()
                messagebox.showerror("CyberSec Agent Error", message)
                root.destroy()
            
            threading.Thread(target=show_error_popup, daemon=True).start()
        except Exception as e:
            print(f"Error showing error popup: {e}")
    
    def exit_application(self, icon=None, item=None):
        """Exit the application"""
        try:
            self.stop_agent()
            if self.icon:
                self.icon.stop()
        except Exception as e:
            print(f"Error during exit: {e}")
    
    def create_menu(self):
        """Create the context menu for the tray icon"""
        try:
            return pystray.Menu(
                pystray.MenuItem("Start Agent", self.start_agent, enabled=lambda item: not self.agent_running),
                pystray.MenuItem("Stop Agent", self.stop_agent, enabled=lambda item: self.agent_running),
                pystray.MenuItem("View Status", self.view_status),
                pystray.MenuItem("Open Dashboard", self.open_dashboard),
                pystray.MenuItem("Exit", self.exit_application)
            )
        except Exception as e:
            print(f"Error creating menu: {e}")
            return None
    
    def monitor_agent(self):
        """Monitor agent process status in background"""
        while True:
            try:
                if self.agent_process and self.agent_running:
                    poll_result = self.agent_process.poll()
                    if poll_result is not None:
                        self.agent_running = False
                        self.status_data['status'] = 'Stopped'
                        self.update_icon()
                        print("Agent process ended")
                
                time.sleep(5)
            except Exception as e:
                print(f"Error monitoring agent: {e}")
                time.sleep(5)
    
    def run(self):
        """Run the tray application"""
        try:
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self.monitor_agent, daemon=True)
            monitor_thread.start()
            
            # Create and run tray icon
            self.icon = pystray.Icon(
                "CyberSec Agent",
                self.create_icon('red'),
                "CyberSec Security Agent",
                self.create_menu()
            )
            
            # Auto-start agent
            self.start_agent()
            
            # Run tray icon (this blocks)
            self.icon.run()
            
        except Exception as e:
            print(f"Error running tray application: {e}")
            sys.exit(1)

def main():
    try:
        app = AgentTrayUI()
        app.run()
    except KeyboardInterrupt:
        print("Application interrupted")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()