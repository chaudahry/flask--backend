# text_processor.py
import re
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer

# Download NLTK data if not already present
try:
    stopwords.words('english')
except LookupError:
    import nltk

    nltk.download('stopwords')
    nltk.download('punkt')
    nltk.download('wordnet')
    nltk.download('omw-1.4')

lemmatizer = WordNetLemmatizer()
stop_words = set(stopwords.words('english'))


def preprocess_text(text):
    # Remove URLs
    text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)
    # Remove mentions and hashtags
    text = re.sub(r'@\w+|#\w+', '', text)
    # Keep letters, numbers, dots, plus and dash
    text = re.sub(r'[^a-zA-Z0-9\s\.\+\-]', '', text)
    # Convert to lowercase
    text = text.lower()
    # Tokenize
    tokens = word_tokenize(text)
    # Remove stop words and lemmatize
    processed_tokens = [lemmatizer.lemmatize(word) for word in tokens if word not in stop_words]
    return " ".join(processed_tokens)


def extract_skills_from_text(text):
    # This is a very basic rule-based skill extraction.
    # For a real application, you'd use a pre-trained NER model (e.g., SpaCy's 'en_core_web_lg' or a custom one)
    # or a comprehensive skill dictionary.

    # Expanded and refined common skills list
    common_skills = [
        "python", "java", "javascript", "react", "node.js", "sql", "aws", "docker",
        "kubernetes", "machine learning", "data analysis", "project management",
        "agile", "scrum", "communication", "leadership", "figma", "photoshop",
        "seo", "marketing", "finance", "hr", "sales", "engineering", "design",
        "cloud", "devops", "backend", "backend", "fullstack", "ui/ux", "data science",
        "artificial intelligence", "cybersecurity", "network", "database", "mobile development",
        "android", "ios", "web development", "content creation", "social media",
        "public relations", "brand management", "market research", "financial analysis",
        "accounting", "auditing", "investment", "recruitment", "employee relations",
        "training", "supply chain", "logistics", "operations management", "product management",
        "business development", "customer service", "technical support", "graphic design",
        "illustration", "video editing", "animation", "autocad", "solidworks",
        "excel", "powerpoint", "word", "microsoft office", "google suite", "tableau", "power bi",
        "sas", "r", "c++", "c#", "go", "ruby", "php", "swift", "kotlin", "typescript",
        "spring", "hibernate", "angular", "vue.js", "django", "flask", "laravel", "symfony",
        "express.js", "mongodb", "postgresql", "mysql", "oracle", "redis", "cassandra",
        "azure", "gcp", "terraform", "ansible", "jenkins", "gitlab ci", "jira", "confluence",
        "salesforce", "sap", "erp", "crm", "qa", "testing", "automation", "manual testing",
        "api", "rest", "graphql", "microservices", "blockchain", "iot", "robotics",
        "natural language processing", "computer vision", "deep learning", "neural networks",
        "statistical analysis", "quantitative analysis", "risk management", "compliance",
        "budgeting", "forecasting", "financial reporting", "tax preparation", "auditing",
        "talent acquisition", "employee engagement", "performance management", "compensation & benefits",
        "organizational development", "change management", "negotiation", "client management",
        "lead generation", "cold calling", "sales strategy", "customer relationship management",
        "autocad", "solidworks", "catia", "revit", "bim", "fea", "cfd", "matlab", "simulink",
        "circuit design", "embedded systems", "firmware", "hardware", "manufacturing processes",
        "supply chain optimization", "inventory management", "logistics planning",
        "user research", "wireframing", "prototyping", "usability testing", "information architecture",
        "interaction design", "visual design", "brand identity", "print design", "digital art",
        "video production", "motion graphics", "3d modeling", "maya", "blender", "cinema 4d",
        "content strategy", "copywriting", "editing", "proofreading", "storytelling",
        "email marketing", "ppc", "google analytics", "social media marketing", "influencer marketing",
        "public speaking", "presentation skills", "problem-solving", "critical thinking",
        "adaptability", "teamwork", "collaboration", "creativity", "innovation", "attention to detail"
    ]

    found_skills = []
    processed_text = text.lower()  # Ensure text is lowercased for matching

    for skill in common_skills:
        # Use word boundaries to avoid partial matches (e.g., 'hr' matching 'shred')
        # Added more robust regex for common variations (e.g., "node js", "node.js")
        if re.search(r'\b' + re.escape(skill).replace('\.', '[\.\s]?') + r'\b', processed_text):
            found_skills.append(skill.replace('.', ''))  # Clean up for display

    return list(set(found_skills))  # Return unique skills


def categorize_resume(text):
    text = text.lower()

    categories = {
        "Tech": ["agile", "algorithm", "android", "angular", "ansible", "api", "api gateway", "arduino",
                 "asp.net", "aws", "azure", "backend", "bash", "big data", "bi tools", "blockchain",
                 "bootstrap", "capacitor", "cassandra", "c", "c++", "c#", "chatbot development", "chakra ui",
                 "cloud", "cloud engineer", "cloud-native", "cloudformation", "coding", "computer vision",
                 "confluence", "cypress", "cybersecurity", "data analyst", "data engineering", "data lakes",
                 "data modeling", "data pipelines", "data preprocessing", "data science", "data warehouse",
                 "data warehousing", "data wrangling", "datadog", "database", "deep learning", "desktop apps",
                 "design patterns", "developer", "development", "devops", "devsecops", "django", "docker",
                 "edge computing", "elastic beanstalk", "end-to-end testing", "encryption", "etl", "event-driven",
                 "express", "fastapi", "feature engineering", "firebase", "flask", "flutter", "frontend",
                 "frontend development", "frontend engineer", "full-stack engineer", "fullstack", "game development",
                 "gan", "git", "github", "gitlab", "glcp", "go", "grafana", "graphql", "grpc", "hadoop", "helm",
                 "heroku", "hive", "huggingface", "https", "iam", "identity access management", "image processing",
                 "infosec", "integration testing", "ios", "iot", "java", "javascript", "jenkins", "jira", "junit",
                 "kanban", "kafka", "keras", "kotlin", "lambda", "laravel", "linux", "load testing", "lstm",
                 "machine learning", "material ui", "matlab", "message queues", "metaverse", "microservices",
                 "mobile apps", "mobile development", "model deployment", "mongodb", "monolith", "mysql",
                 "natural language processing", "network", "network engineer", "neural networks", "next.js",
                 "nlp", "node.js", "nosql", "numpy", "oauth", "observability", "ocr", "openapi", "oracle",
                 "pandas", "pair programming", "penetration testing", "perl", "performance testing", "php",
                 "pig", "playwright", "postgresql", "power bi", "postgres", "programmer", "programming",
                 "progressive web apps", "prometheus", "pub-sub", "pytest", "pwa", "python", "qa engineer",
                 "r", "rails", "raspberry pi", "react", "react native", "redshift", "rest", "rest api", "r&d",
                 "robotics", "ruby", "rust", "scala", "scrum", "scikit-learn", "selenium", "serverless",
                 "site reliability", "site reliability engineer", "smart contracts", "snowflake", "soapui",
                 "soc analyst", "software", "software architecture", "software engineer", "solidity", "spark",
                 "spring boot", "sql", "sqlite", "ssl", "sre", "svelte", "swift", "swiftui", "tableau",
                 "tailwind", "terraform", "test automation", "testing", "time series", "tls", "trunk-based development",
                 "transformers", "typescript", "unit testing", "vercel", "version control", "vulnerability assessment",
                 "vue.js", "web3", "web app development", "web development", "windows server", "xamarin",
                 "zero trust"],
        "Marketing": ["advertisement", "advertising", "affiliate marketing", "analytics", "b2b marketing",
                      "b2c marketing", "brand", "brand awareness", "brand management", "campaign",
                      "click-through rate", "competitive analysis", "content", "content creation",
                      "content marketing", "content strategy", "conversion optimization", "copywriting",
                      "crm", "customer acquisition", "customer engagement", "customer journey",
                      "customer retention", "data-driven marketing", "demand generation", "digital advertising",
                      "digital marketing", "display advertising", "drip campaigns", "email campaigns",
                      "email marketing", "event marketing", "facebook ads", "go-to-market strategy",
                      "google ads", "google analytics", "growth hacking", "inbound marketing",
                      "influencer marketing", "instagram marketing", "keyword research", "landing pages",
                      "lead generation", "lead nurturing", "linkedin ads", "loyalty marketing",
                      "market analysis", "market research", "marketing", "marketing automation",
                      "marketing funnel", "marketing operations", "marketing strategy", "media buying",
                      "media planning", "mobile marketing", "omnichannel marketing", "performance marketing",
                      "persona development", "ppc", "pr", "product marketing", "programmatic advertising",
                      "public relations", "retargeting", "roi", "sales enablement", "search engine marketing",
                      "search engine optimization", "sem", "seo", "social listening", "social media",
                      "social media management", "social media marketing", "sponsorship marketing",
                      "storytelling", "strategy", "tiktok marketing", "twitter ads", "user acquisition",
                      "video marketing", "viral marketing", "web analytics", "webinars", "youtube ads"],
        "Design": ["3d animation", "3d design", "3d modeling", "adobe after effects", "adobe creative cloud",
                   "adobe illustrator", "adobe indesign", "adobe photoshop", "adobe xd", "animation",
                   "architectural design", "augmented reality design", "blender", "branding", "canva",
                   "character design", "color theory", "concept art", "creative", "css", "design", "design systems",
                   "digital art", "fashion design", "figma", "game design", "graphic", "graphic design",
                   "illustration", "illustrator", "industrial design", "information architecture",
                   "interaction design", "interior design", "logo design", "material design", "mockups",
                   "motion design", "motion graphics", "photoshop", "portfolio", "presentation design",
                   "print design", "product design", "prototyping", "responsive design", "sketch",
                   "storyboarding", "style guide", "typography", "ui designer", "ui/ux", "user experience",
                   "user flows", "user interface", "ux design", "ux designer", "vector graphics", "visual",
                   "visual communication", "visual design", "vr design", "web design", "webflow", "wireframing"],
        "Finance": ["accounting", "accounts payable", "accounts receivable", "aml", "asset allocation",
                    "asset management", "audit", "auditor", "bank reconciliation", "banking",
                    "bookkeeping", "budget", "business analysis", "capital budgeting", "capital markets",
                    "cash flow", "cfa", "cma", "compliance", "corporate finance", "cost accounting",
                    "cpa", "credit analysis", "credit risk", "derivatives", "due diligence", "econometrics",
                    "economics", "equity research", "esg finance", "external audit", "faas", "finance",
                    "financial accounting", "financial analysis", "financial auditor", "financial forecasting",
                    "financial modeling", "financial planning", "financial reporting", "fintech",
                    "fixed income", "forensic accounting", "forecasting", "fund accounting", "fund management",
                    "gaap", "hedge funds", "ifr", "ifrs", "income statement", "internal audit",
                    "investment", "investment banking", "invoice processing", "kpi analysis", "mergers and acquisitions",
                    "msa", "mutual funds", "payroll", "portfolio", "portfolio management", "private equity",
                    "profit and loss", "quantitative finance", "reconciliation", "regulatory compliance",
                    "return on investment", "revenue recognition", "risk assessment", "risk management",
                    "sap fico", "securities", "statutory audit", "tax", "tax planning", "treasury",
                    "variance analysis", "wealth management", "working capital"],
        "HR": ["applicant tracking system", "ats", "benefits", "career development", "change management",
               "compensation", "compliance training", "conflict resolution", "diversity and inclusion",
               "employee benefits", "employee engagement", "employee handbook", "employee lifecycle",
               "employee onboarding", "employee relations", "employer branding", "exit interviews",
               "grievance handling", "hr", "hr analytics", "hr audit", "hr business partner", "hr compliance",
               "hr generalist", "hr metrics", "hr operations", "hr policies", "hr strategy", "hr technology",
               "hrbp", "hris", "hrms", "human capital management", "human resources", "internal mobility",
               "job analysis", "job design", "job evaluation", "kpis", "labor law", "learning and development",
               "lms", "manager training", "onboarding", "organizational culture", "organizational development",
               "payroll", "performance appraisal", "performance management", "personnel management",
               "policy development", "recruiting", "recruitment", "remote onboarding", "retention strategy",
               "reward management", "succession planning", "talent acquisition", "talent development",
               "talent management", "termination process", "training", "training and development",
               "workforce", "workforce analytics", "workforce planning"],
        "Sales": ["account executive", "account management", "b2b sales", "b2c sales", "business development",
                  "channel sales", "client engagement", "client relations", "cold calling", "commission",
                  "consultative selling", "crm", "customer acquisition", "customer retention", "deal closing",
                  "direct sales", "enterprise sales", "field sales", "inside sales", "key account management",
                  "lead generation", "negotiation", "outside sales", "pipeline management", "product demo",
                  "quota", "relationship building", "revenue", "sales", "sales analysis", "sales enablement",
                  "sales forecasting", "sales funnel", "sales management", "sales operations", "sales planning",
                  "sales process", "sales strategy", "salesforce", "solution selling", "territory management",
                  "upselling", "value proposition"],
        "Engineering": ["aerospace", "automation", "biomedical engineering", "cad", "circuit design", "civil",
                        "chemical", "design", "electrical", "embedded systems", "engineer", "engineering analysis",
                        "engineering design", "engineering drawing", "engineering management", "firmware",
                        "hardware design", "hvac", "industrial engineering", "instrumentation", "maintenance engineering",
                        "manufacturing", "materials science", "matlab", "mechanical", "mechatronics", "plant engineering",
                        "process engineering", "product development", "product engineering", "project engineering",
                        "quality engineering", "r&d", "research and development", "robotics", "simulation",
                        "solidworks", "structural", "sustainable engineering", "systems"],
        "Social Media": ["analytics dashboard", "audience engagement", "buffer", "community engagement",
                         "community management", "content calendar", "content creation", "engagement",
                         "facebook", "hashtag strategy", "hootsuite", "influencer", "instagram",
                         "linkedin", "online community", "platform management", "reels", "schedule posts",
                         "social listening", "social media", "social media analytics", "social media management",
                         "social media marketing", "social media optimization", "social media platforms",
                         "social media scheduling", "social media strategy", "tiktok", "trending content", "twitter",
                         "user engagement", "youtube"],
        "Operations": ["6 sigma", "business continuity", "business operations", "capacity planning", "continuous improvement",
                       "distribution", "enterprise resource planning", "erp", "inventory control", "inventory management",
                       "kaizen", "lean manufacturing", "logistics", "materials management", "operations", "operational efficiency",
                       "operational excellence", "order fulfillment", "pmo", "process engineering", "process improvement",
                       "production planning", "project management office", "procurement", "quality assurance",
                       "quality control", "resource planning", "supply chain", "supply chain management", "vendor management",
                       "warehouse management"],
        "Healthcare": ["biotechnology", "clinical", "clinical research", "dentist", "doctor", "epidemiology", "health administration",
                       "health information management", "health policy", "healthcare", "healthcare analytics", "hospital",
                       "medical", "medical billing", "medical records", "mental health", "nurse", "occupational therapy",
                       "patient care", "pharmacist", "pharmaceutical", "physical therapy", "physician", "public health",
                       "radiology", "research", "telemedicine", "therapist"],
        "Education": ["academic administration", "academic advising", "blended learning", "classroom management",
                      "curriculum development", "distance education", "e-learning", "education", "educational leadership",
                      "educational psychology", "educational technology", "higher education", "instructor", "k-12",
                      "learning assessment", "lesson planning", "lms", "online teaching", "pedagogy", "professor",
                      "remote instruction", "school administration", "special education", "student affairs",
                      "student engagement", "syllabus design", "teacher", "teaching certification", "teaching methods",
                      "training development", "tutoring"],
        "Customer Service": ["call center", "client experience", "client success", "client support", "contact center", "crm tools",
                             "customer care", "customer communication", "customer engagement", "customer experience",
                             "customer feedback", "customer interaction", "customer relations", "customer satisfaction",
                             "customer service", "customer support", "escalation handling", "help desk", "live chat support",
                             "phone support", "problem resolution", "service desk", "support specialist", "technical support",
                             "ticketing system", "troubleshooting", "user support"],
        "Legal": ["affidavit", "attorney", "civil law", "compliance", "contract law", "corporate law", "court filings",
                  "criminal law", "discovery", "dispute resolution", "esq", "ethics compliance", "family law", "intellectual property",
                  "juris", "law", "law firm", "legal", "legal advisory", "legal assistant", "legal compliance",
                  "legal counsel", "legal documentation", "legal research", "legal writing", "litigation", "paralegal",
                  "real estate law", "regulatory affairs", "risk and compliance", "trial preparation"],
        "Project Management": ["agile coach", "asana", "backlog grooming", "baseline management", "budget forecasting",
                               "budget management", "change management", "confluence", "cost control", "gantt charts",
                               "jira", "kanban", "milestone tracking", "portfolio management", "program management",
                               "project lifecycle", "project management", "project planning", "pmp", "product lifecycle",
                               "product owner", "progress tracking", "project coordination", "project delivery",
                               "project execution", "resource allocation", "risk analysis", "risk management", "roadmap planning",
                               "scrum", "scrum master", "stakeholder communication", "stakeholder management", "status reporting",
                               "trello", "waterfall model", "work breakdown structure"]
        }

    # Check for category matches
    for category, keywords_list in categories.items():
        for keyword in keywords_list:
            if re.search(r'\b' + re.escape(keyword) + r'\b', text):
                return category

    # If no specific category matches, try to infer from general terms
    if any(k in text for k in ["analyst", "consultant", "specialist", "manager", "coordinator"]):
        return "Other"

    return "Uncategorized"

