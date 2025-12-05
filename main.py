import re
import tkinter as tk
from tkinter import ttk
import math
import time

# --- CONSTANTS FOR ADVANCED ANALYSIS ---

# 1. Simple Dictionary/Breach Approximation (V1 & V6)
COMMON_WEAK_WORDS = [
    "password", "123456", "qwerty", "admin", "qazwsx", "football", "summer", 
    "spring", "welcome", "secure", "secret", "test", "shadow", "master", 
    "default", "change", "dropbox", "america", "india", "ganesh", "shahan"
]

# 2. V8: AI Pattern Heuristic Segments (Simulated)
# These are common components users combine to create predictable passwords (e.g., ShadowMaster, DragonFire123)
COMPLEX_WEAK_COMBINATIONS = [
    "master", "shadow", "dragon", "ninja", "firewall", "dark", "light", 
    "ocean", "fire", "secure", "strong", "magic", "power", "happy", "love"
]


# 3. Keyboard Patterns (V2)
KEYBOARD_PATTERNS = [
    r"asdfg", r"zxcvb", r"qwert", r"yuiop", # Rows
    r"12345", r"54321", r"abcde", r"edcba", # Simple sequences
    r"qaz", r"wsx", r"edc", r"rfv", # Diagonal/vertical patterns
    r"789", r"987", r"456", r"654", r"258", r"147" # Numpad/keyboard blocks
]

# 4. Time-to-Crack Estimation (V5)
# This uses the assumed cracking speed of 10 billion hashes/second (10^10)
CRACK_SPEED_PER_SECOND = 1e10 
SECONDS_IN = {
    'millisecond': 0.001,
    'second': 1,
    'minute': 60,
    'hour': 3600,
    'day': 86400,
    'month': 2592000,
    'year': 31536000,
    'century': 3153600000
}

# --- STRENGTH LOGIC BASED ON ENTROPY ---

def get_character_pool_size(password):
    """Calculates the size of the character set (R) used in the password."""
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"\d", password):
        pool_size += 10
    # Custom symbols (covers common punctuation and special chars)
    if re.search(r"[^a-zA-Z0-9\s]", password):
        pool_size += 33 
    return max(1, pool_size) # Must be at least 1

def calculate_entropy_bits(password):
    """
    V4: Calculates cryptographic entropy (bits of randomness).
    Entropy = Length * log2(Pool Size)
    """
    length = len(password)
    if length == 0:
        return 0
    
    pool_size = get_character_pool_size(password)
    entropy = length * math.log2(pool_size)
    return entropy

def estimate_crack_time(entropy_bits):
    """
    V5: Estimates the time to crack based on entropy and assumed GPU speed.
    """
    if entropy_bits <= 0:
        return "Instantly"
    
    # Total possible combinations (2^E)
    total_combinations = math.pow(2, entropy_bits)
    
    # Estimated seconds to crack
    seconds = total_combinations / CRACK_SPEED_PER_SECOND
    
    # Categorize time for human readability
    if seconds < SECONDS_IN['millisecond']:
        return "Instantly (< 1 ms)"
    elif seconds < 1:
        ms = seconds * 1000
        return f"{ms:.2f} milliseconds"
    elif seconds < SECONDS_IN['minute']:
        return f"{seconds:.2f} seconds"
    elif seconds < SECONDS_IN['hour']:
        minutes = seconds / SECONDS_IN['minute']
        return f"{minutes:.2f} minutes"
    elif seconds < SECONDS_IN['day']:
        hours = seconds / SECONDS_IN['hour']
        return f"{hours:.2f} hours"
    elif seconds < SECONDS_IN['year']:
        days = seconds / SECONDS_IN['day']
        return f"{days:.2f} days"
    elif seconds < SECONDS_IN['century']:
        years = seconds / SECONDS_IN['year']
        return f"{years:.2f} years"
    else:
        centuries = seconds / SECONDS_IN['century']
        return f"{centuries:.2f} centuries"


def calculate_modified_score(password, entropy_bits):
    """
    Combines Entropy with deductions for known weaknesses (V1, V2, V3, V7, V8).
    The deductions reduce the final effective score (entropy) to reflect real-world weakness.
    """
    score = entropy_bits # Start the score as the maximum theoretical entropy
    
    password_lower = password.lower()

    # --- Deductions ---

    # V1 & V6: Dictionary/Breach Check (Heavy Penalty)
    for word in COMMON_WEAK_WORDS:
        if word in password_lower:
            # Huge penalty for containing a common word or breach password
            score -= 20 
            break

    # V2: Keyboard Pattern Detection (Medium Penalty)
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            score -= 10
            break

    # V8: AI Pattern Heuristic (Simulated Contextual Detection) (Severe Penalty)
    # Checks for composite weak phrases (e.g., 'MasterFirewall') and common word/digit combos
    is_ai_weak = False
    for word1 in COMPLEX_WEAK_COMBINATIONS:
        # Check for Word-Word concatenation
        for word2 in COMPLEX_WEAK_COMBINATIONS:
            if word1 != word2 and f"{word1}{word2}" in password_lower:
                score -= 30 
                is_ai_weak = True
                break
        if is_ai_weak: break
        
        # Check for Word + Digit + Word (e.g., 'Shadow123Master')
        if re.search(f"{word1}\d+[a-z]+", password_lower):
             score -= 20
             is_ai_weak = True
             break
        
        # Check for Word + Digits at the end (e.g., 'Dragon1990')
        if re.search(f"{word1}\d{{3,4}}$", password_lower):
             score -= 20
             is_ai_weak = True
             break


    # V3: Substring Repetition Logic (e.g., 'abcabc')
    # Check for repeating patterns of length 2 or 3
    length = len(password)
    if length >= 4:
        # Check for 2-character repeat (e.g., 'abab')
        if re.search(r"(.{2})\1+", password):
            score -= 15
        # Check for 3-character repeat (e.g., 'abcabc')
        if re.search(r"(.{3})\1+", password):
            score -= 15

    # Original Deduction for Repeated Characters (e.g., 'aaaaa')
    repeat_match = re.findall(r"(.)\1{2,}", password)
    if repeat_match:
        score -= len(repeat_match) * 10 
    
    # V7: Predictable Component Detection (Name + Year + Symbol Approximation)
    # Check if a 4-digit number (year) is combined with a common word/name
    year_pattern = r"(19|20)\d{2}"
    
    contains_year = re.search(year_pattern, password) is not None
    contains_symbol = re.search(r"[^a-zA-Z0-9\s]", password) is not None
    
    if contains_year and contains_symbol:
        for word in COMMON_WEAK_WORDS:
            # Check if a known word is near the year/symbol combo
            if re.search(f"{word}.*{year_pattern}", password_lower) or re.search(f"{year_pattern}.*{word}", password_lower):
                 score -= 25 # Severe penalty for predictable components
                 break

    # Original Deduction for Simple Sequences (e.g., '123' or 'abc')
    if re.search(r"(123|abc|xyz|qwerty)", password, re.IGNORECASE):
           score -= 10
    
    return max(0, round(score))


def get_strength_details(password):
    """Maps score to level, color, feedback, and calculates Time-to-Crack."""
    length = len(password)
    
    if length == 0:
        return {"score": 0, "strength": "No Password", "color": "#D1D5DB", "percent": 0, "time_to_crack": "N/A", "feedback": ["Please enter a password to check its strength."]}

    # 1. Calculate theoretical entropy (V4)
    initial_entropy = calculate_entropy_bits(password)
    
    # 2. Apply deductions to get effective entropy
    effective_entropy = calculate_modified_score(password, initial_entropy)
    
    # 3. Estimate crack time (V5)
    time_to_crack = estimate_crack_time(effective_entropy)

    # --- Level Classification based on Effective Entropy ---
    
    color = "#D1D5DB"
    percent = min(100, effective_entropy * 100 / 75) # Scale to 100 based on 75 bits being excellent
    
    if effective_entropy >= 65:
        strength = "Excellent (Uncrackable)"
        color = "#10B981"  # Emerald Green
    elif effective_entropy >= 51:
        strength = "Strong"
        color = "#059669"  # Dark Green
    elif effective_entropy >= 35:
        strength = "Moderate"
        color = "#F59E0B"  # Yellow/Amber
    elif effective_entropy >= 15:
        strength = "Weak"
        color = "#EF4444"  # Red
    else:
        strength = "Too Weak"
        color = "#B91C1C"  # Dark Red
    
    
    # --- Detailed Feedback Generation (Expanded) ---
    feedback = []

    # Check for inclusion of character types
    checks = {
        'Lowercase letters (a-z)': re.search(r"[a-z]", password),
        'Uppercase letters (A-Z)': re.search(r"[A-Z]", password),
        'Digits (0-9)': re.search(r"\d", password),
        'Symbols (!@#$)': re.search(r"[^a-zA-Z0-9\s]", password)
    }

    # Length Feedback
    if length < 10:
        feedback.append(f"❌ Length: Must be at least 10 characters. Currently {length}.")
    else:
        feedback.append(f"✅ Length: Good ({length} chars).")
    
    # Complexity Feedback
    for key, passed in checks.items():
        if not passed:
            feedback.append(f"❌ Complexity: Include at least one {key}.")
        else:
            feedback.append(f"✅ Complexity: Includes {key}.")

    # V8 Feedback (AI Heuristic)
    is_ai_weak = False
    for word1 in COMPLEX_WEAK_COMBINATIONS:
        for word2 in COMPLEX_WEAK_COMBINATIONS:
            if word1 != word2 and f"{word1}{word2}" in password.lower():
                feedback.append("❌ AI Heuristic (V8): Detects concatenated common words (e.g., 'masterfirewall'). Highly predictable.")
                is_ai_weak = True
                break
        if is_ai_weak: break
        if re.search(f"{word1}\d+[a-z]+", password.lower()) or re.search(f"{word1}\d{{3,4}}$", password.lower()):
             feedback.append("❌ AI Heuristic (V8): Detects common word combined with short numbers/years (e.g., 'shadow1990').")
             is_ai_weak = True
             break


    # V1/V6 Pattern Deduction Feedback
    is_weak_word = False
    for word in COMMON_WEAK_WORDS:
        if word in password.lower():
            feedback.append(f"❌ Breach Risk (V6): Contains '{word}' which is a common dictionary word or breached password.")
            is_weak_word = True
            break
            
    if not is_weak_word and not is_ai_weak and effective_entropy < initial_entropy:
        # Generic warning for other pattern deductions if no specific word was found
        feedback.append("⚠️ Warning: Contains easily guessable patterns (V2/V3/V7).")


    # V3/V7 Pattern Feedback
    if re.search(r"(.{2})\1+", password) or re.search(r"(.{3})\1+", password):
        feedback.append("❌ Repetition (V3): Contains repeated blocks (e.g., 'abcabc').")
    
    if re.search(r"(.)\1{2,}", password):
        feedback.append("⚠️ Repetition: Contains triple or more repetitive characters (e.g., 'aaa').")

    if re.search(r"(123|abc|xyz|qwerty)", password, re.IGNORECASE):
        feedback.append("⚠️ Warning: Contains simple sequential patterns ('123', 'abc').")

    return {
        "score": effective_entropy, 
        "strength": strength, 
        "color": color, 
        "percent": percent, 
        "time_to_crack": time_to_crack, 
        "feedback": feedback
    }

# --- Tkinter GUI Application Class (Aesthetics Retained) ---

class PasswordCheckerApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Password Strength Analyzer")
        master.geometry("500x520") # Slightly taller window for new info
        master.resizable(False, False)
        master.configure(background='#F0F0F0')

        # Configure modern styling
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Main.TFrame', background='#FFFFFF', borderwidth=1, relief="flat")
        style.configure('TLabel', background='#FFFFFF', font=('Segoe UI', 10), foreground='#333333')
        style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'), foreground='#2563EB')
        style.configure('Bold.TLabel', font=('Segoe UI', 11, 'bold'))
        
        # Customizing the Progressbar
        style.layout('Custom.Horizontal.TProgressbar', 
                      [('Horizontal.Progressbar.trough', 
                        {'children': [('Horizontal.Progressbar.pbar', {'side': 'left', 'sticky': 'ns'})],
                         'sticky': 'nsew'})])
        style.configure('Custom.Horizontal.TProgressbar', troughcolor='#E5E7EB', borderwidth=0, thickness=12)


        # Main Frame (Container for content)
        self.main_frame = ttk.Frame(master, style='Main.TFrame', padding="25 20 25 20")
        self.main_frame.pack(fill='both', expand=True, padx=15, pady=15)

        # Title
        ttk.Label(self.main_frame, text="Password Strength Analyzer", style='Title.TLabel').pack(pady=(0, 15))
        
        # Input Label and Field
        ttk.Label(self.main_frame, text="Enter Password:").pack(anchor='w', pady=(5, 2))
        self.password_entry = ttk.Entry(self.main_frame, show="*", width=50, font=('Consolas', 12), foreground='#222')
        self.password_entry.pack(fill='x', ipady=8)
        self.password_entry.bind('<KeyRelease>', self.check_strength_event)

        # Strength Bar Label and Progress Bar
        ttk.Label(self.main_frame, text="Strength Level:").pack(anchor='w', pady=(15, 5))
        
        self.strength_bar = ttk.Progressbar(self.main_frame, orient='horizontal', length=450, mode='determinate', style='Custom.Horizontal.TProgressbar')
        self.strength_bar.pack(fill='x', pady=0)
        
        # Strength Text and Info Container
        info_container = ttk.Frame(self.main_frame, style='Main.TFrame')
        info_container.pack(fill='x', pady=(5, 15))

        # Strength Text (Left aligned and prominent)
        self.strength_label = ttk.Label(info_container, text="No Password", font=('Segoe UI', 14, 'bold'), foreground='#444')
        self.strength_label.pack(side='left')
        
        # Time-to-Crack (Right aligned and crucial info)
        self.time_label = ttk.Label(info_container, text="Cracking Time: N/A", font=('Segoe UI', 10, 'bold'), foreground='#CC0000') # Start in red/danger color
        self.time_label.pack(side='right')

        # Score (Entropy Bits)
        self.score_label = ttk.Label(self.main_frame, text="Effective Entropy: 0 bits", font=('Segoe UI', 9), foreground='#888')
        self.score_label.pack(anchor='e')

        # Feedback Section
        ttk.Label(self.main_frame, text="Security Checklist (Includes AI Heuristic):", style='Bold.TLabel').pack(anchor='w', pady=(10, 5))
        
        self.feedback_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        self.feedback_frame.pack(fill='both', expand=True)
        
        # Text widget for feedback
        self.feedback_text = tk.Text(self.feedback_frame, height=10, width=50, state='disabled', wrap='word', 
                                     borderwidth=1, relief="solid", font=('Consolas', 10), padx=8, pady=8, 
                                     background='#F9F9F9', foreground='#333333', selectbackground='#C3D9FF')
        self.feedback_text.pack(fill='both', expand=True)
        
        # Initial check to set the default state
        self.check_strength_event(None)

    def check_strength_event(self, event):
        """Called on every key release in the password field."""
        password = self.password_entry.get()
        details = get_strength_details(password) # Updated to use the new details structure

        # Update Strength Label
        self.strength_label.config(text=details['strength'], foreground=details['color'])
        
        # Update Time-to-Crack Label (V5)
        self.time_label.config(text=f"Cracking Time: {details['time_to_crack']}")
        # Adjust Time Label Color based on strength
        time_color = "#CC0000" if details['score'] < 35 else "#F59E0B" if details['score'] < 51 else "#059669"
        self.time_label.config(foreground=time_color)


        # Update Score Label (V4: Entropy)
        self.score_label.config(text=f"Effective Entropy: {details['score']} bits")

        # Update Progress Bar Color and Value
        style = ttk.Style()
        style_name = f"{details['color']}.Custom.Horizontal.TProgressbar"
        style.configure(style_name, background=details['color'])
        self.strength_bar.config(style=style_name, value=details['percent'])
        
        # Update Feedback Text Area
        self.feedback_text.config(state='normal')
        self.feedback_text.delete(1.0, tk.END)
        
        # Insert feedback lines
        if password:
            for line in details['feedback']:
                self.feedback_text.insert(tk.END, line + '\n')
        else:
            self.feedback_text.insert(tk.END, "Start typing your password to see the analysis.")

        self.feedback_text.config(state='disabled')


if __name__ == "__main__":
    # Compile regex patterns for efficiency 
    re.compile(r"[a-z]")
    re.compile(r"[A-Z]")
    re.compile(r"\d")
    re.compile(r"[^a-zA-Z0-9\s]")
    re.compile(r"(.)\1{2,}")
    re.compile(r"(.{2})\1+")
    re.compile(r"(.{3})\1+")
    re.compile(r"(19|20)\d{2}")
    
    # Initialize the desktop window
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()
