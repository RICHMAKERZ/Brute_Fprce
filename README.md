# مشروع البحث عن العناوين باستخدام Brute Force

هذا المشروع يهدف إلى البحث عن عناوين محددة (Bitcoin Addresses) من خلال توليد مفاتيح خاصة (Private Keys) بشكل عشوائي وتحويلها إلى عناوين باستخدام خوارزميات التشفير. يتم استخدام تقنية **Brute Force** مع دعم **Multiprocessing** لتسريع العملية.

## المتطلبات

- **بايثون 3.10**: يجب تثبيت بايثون بالإصدار 3.10 حتى 3.12
- **المكتبات المطلوبة**: قم بتثبيت المكتبات من خلال power shell
  - `ecdsa`: لتوليد المفاتيح الخاصة والعناوين.
  - `tqdm`: لعرض شريط التقدم.
  - `colorama`: لإضافة ألوان إلى النصوص في الطرفية.
  - `hashlib`: لتوليد الهاشات (SHA256, RIPEMD160).
  - `multiprocessing`: لتقسيم العملية على عدة أنوية معالجة.

## كيفية تثبيت المكتبات


يمكن تثبيت المكتبات المطلوبة باستخدام الأمر التالي:
pip install ecdsa tqdm colorama






كيفية تشغيل الكود
تنزيل الكود: قم بتنزيل الكود واحفظه في مجلد على جهازك.

إعداد ملف التحدي: قم بإنشاء ملف نصي باسم challenge.txt في نفس المجلد، وضع فيه العناوين التي تريد البحث عنها (عنوان واحد في كل سطر).

تشغيل الكود: قم بتشغيل الكود باستخدام الأمر التالي:



python Brute_force.py





شرح الكود
1. تحميل العناوين المستهدفة
يتم تحميل العناوين من ملف challenge.txt باستخدام الدالة load_targets. إذا لم يتم العثور على الملف، سيتم إظهار رسالة خطأ.

2. توليد المفاتيح الخاصة
يتم توليد المفاتيح الخاصة بشكل عشوائي باستخدام الدالة generate_private_key. يتم إضافة قفزات عشوائية لزيادة التنوع في المفاتيح المولدة.

3. تحويل المفتاح الخاص إلى عنوان
يتم تحويل المفتاح الخاص إلى عنوان Bitcoin باستخدام الدالة derive_address. يتم استخدام خوارزميات SHA256 و RIPEMD160 لتوليد العنوان.

4. البحث باستخدام Brute Force
يتم استخدام تقنية Multiprocessing لتقسيم العملية على عدة أنوية معالجة، مما يسرع عملية البحث. يتم تحديث شريط التقدم باستخدام مكتبة tqdm.

5. حفظ النتائج
يتم حفظ العناوين التي تم العثور عليها مع مفاتيحها الخاصة في ملف I_win.txt باستخدام الدالة save_results.

مثال لملف challenge.txt

1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
مثال لملف I_win.txt

Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa, Private Key: b9c27669757b7f281868e3e2eb2c5c20bd60c2834ab4ecf036db88ec53b8d110
ملاحظات
الكود مصمم للعمل على أنظمة تدعم Multiprocessing.

يمكن تعديل نطاق البحث (start_hex و end_hex) ليتناسب مع احتياجاتك.

يتم عرض سرعة البحث (عدد المفاتيح التي تم فحصها في الثانية) أثناء التشغيل.مشروع البحث عن عناوين البتكوين من خلال  فك التشفير 
