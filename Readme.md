LANGKAH LANGKAH RUN PROJEKNYA

<!-- buat virtual env baru -->

cd folder/repo/kamu
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

<!-- install requierment yang di perlukan -->
pip install -r requirements.txt

<!-- modelnya download di sini kalau belum ada -->
https://drive.google.com/file/d/1VcxnqBhCiSAm8eIFxQ4IFHl7sn65mTJw/view?usp=sharing

<!-- buat databasenya di my sql (autocutting_pmld)  -->

<!-- Set up FLASK -->
export FLASK_APP=app.py  # atau `set` di Windows
flask db init
flask db migrate -m "Initial"
flask db upgrade

<!-- Run BE -->
flask run
