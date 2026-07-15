"""Static dummy data for the demo college website.

No database, as specified -- everything here is an in-memory Python
literal. RESULTS/LIBRARY_BOOKS exist so the Results and Library pages
have something realistic to search, which is what makes the SQL
injection demo meaningful (a payload in ?roll_no=... or ?q=... actually
gets processed by a lookup, not just ignored).
"""

COLLEGE_NAME = "Meridian State College"

DEPARTMENTS = [
    {"name": "Computer Science", "hod": "Dr. Anita Rao", "description": "Programming, AI, systems, and networks."},
    {"name": "Electronics & Communication", "hod": "Dr. Rajesh Menon", "description": "Circuits, embedded systems, and signal processing."},
    {"name": "Mechanical Engineering", "hod": "Dr. Priya Nair", "description": "Design, thermodynamics, and manufacturing."},
    {"name": "Civil Engineering", "hod": "Dr. Suresh Kumar", "description": "Structures, materials, and urban planning."},
    {"name": "Commerce & Management", "hod": "Dr. Lakshmi Iyer", "description": "Accounting, finance, and business administration."},
]

FACULTY = [
    {"name": "Dr. Anita Rao", "department": "Computer Science", "designation": "Professor & HoD", "email": "anita.rao@meridian.edu"},
    {"name": "Mr. Vikram Shah", "department": "Computer Science", "designation": "Assistant Professor", "email": "vikram.shah@meridian.edu"},
    {"name": "Dr. Rajesh Menon", "department": "Electronics & Communication", "designation": "Professor & HoD", "email": "rajesh.menon@meridian.edu"},
    {"name": "Ms. Deepa Pillai", "department": "Electronics & Communication", "designation": "Lecturer", "email": "deepa.pillai@meridian.edu"},
    {"name": "Dr. Priya Nair", "department": "Mechanical Engineering", "designation": "Professor & HoD", "email": "priya.nair@meridian.edu"},
    {"name": "Dr. Suresh Kumar", "department": "Civil Engineering", "designation": "Professor & HoD", "email": "suresh.kumar@meridian.edu"},
    {"name": "Dr. Lakshmi Iyer", "department": "Commerce & Management", "designation": "Professor & HoD", "email": "lakshmi.iyer@meridian.edu"},
]

PLACEMENTS = [
    {"year": 2025, "company": "Infotech Solutions", "students_placed": 42, "avg_package_lpa": 6.2},
    {"year": 2025, "company": "Orbit Systems", "students_placed": 18, "avg_package_lpa": 8.5},
    {"year": 2024, "company": "BlueWave Analytics", "students_placed": 27, "avg_package_lpa": 7.1},
    {"year": 2024, "company": "Coastal Manufacturing Ltd", "students_placed": 15, "avg_package_lpa": 5.4},
    {"year": 2023, "company": "Infotech Solutions", "students_placed": 35, "avg_package_lpa": 5.8},
]

# Keyed by roll number, deliberately small and fixed. The Results page
# does a plain dict lookup -- there is no real database and therefore no
# actual SQL injection vulnerability here. A SQLi-shaped payload in
# ?roll_no=... simply won't match any key and the page reports "not
# found" -- what the demo shows is that the *request itself* gets
# logged and classified by the detection pipeline, not a working
# exploit against a backend that doesn't exist.
RESULTS = {
    "CS2021001": {"name": "Arjun Mehta", "course": "B.Tech Computer Science", "semester": 6, "gpa": 8.7},
    "CS2021002": {"name": "Sneha Kulkarni", "course": "B.Tech Computer Science", "semester": 6, "gpa": 9.1},
    "EC2021015": {"name": "Rohit Bansal", "course": "B.Tech Electronics & Communication", "semester": 6, "gpa": 7.9},
    "ME2021030": {"name": "Kavya Reddy", "course": "B.Tech Mechanical Engineering", "semester": 6, "gpa": 8.2},
    "CE2021042": {"name": "Farhan Sheikh", "course": "B.Tech Civil Engineering", "semester": 6, "gpa": 7.5},
}

LIBRARY_BOOKS = [
    {"title": "Introduction to Algorithms", "author": "Cormen, Leiserson, Rivest, Stein", "category": "Computer Science", "available": True},
    {"title": "Operating System Concepts", "author": "Silberschatz, Galvin, Gagne", "category": "Computer Science", "available": False},
    {"title": "Principles of Electronics", "author": "V.K. Mehta", "category": "Electronics", "available": True},
    {"title": "Engineering Mechanics", "author": "R.S. Khurmi", "category": "Mechanical", "available": True},
    {"title": "Structural Analysis", "author": "R.C. Hibbeler", "category": "Civil", "available": False},
    {"title": "Financial Accounting", "author": "Jane Doe", "category": "Commerce", "available": True},
]

# Demo-only credentials for the Student Login brute-force target. Not a
# real auth system -- one fixed username/password pair is the only
# combination that ever succeeds.
DEMO_STUDENT_USERNAME = "student1"
DEMO_STUDENT_PASSWORD = "demo123"
