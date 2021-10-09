-- הגדרת טבלאות
CREATE TABLE Users (
	UserID int IDENTITY PRIMARY KEY NOT NULL,
	FirstName nvarchar(30) NOT NULL,
	LastName nvarchar(30) NOT NULL,
	Username nvarchar(30) NOT NULL,
	Email nvarchar(120) NOT NULL,
	PasswordHash varbinary(max) NOT NULL,
	PasswordSalt nvarchar(100) NOT NULL
)
GO

CREATE TABLE Countries
(
CountryCode int IDENTITY PRIMARY KEY NOT NULL,
CountryName nvarchar(50) NOT NULL
)
GO

CREATE TABLE Categories
(
CategoryCode int IDENTITY PRIMARY KEY NOT NULL,
CategoryName nvarchar(100) NOT NULL
)
GO

CREATE TABLE SubCategories
(
SubCategoryCode int IDENTITY PRIMARY KEY NOT NULL,
CategoryCode int FOREIGN KEY REFERENCES Categories (CategoryCode) NOT NULL,
SubCategoryName nvarchar(100) NOT NULL
)
GO

CREATE TABLE Conditions
(
ConditionCode int IDENTITY PRIMARY KEY NOT NULL,
ConditionName nvarchar(30) NOT NULL
)
GO

CREATE TABLE SellTypes
(
SellTypeCode int IDENTITY PRIMARY KEY NOT NULL,
SellTypeName nvarchar(30) NOT NULL
)
GO

CREATE TABLE UserAddresses
(
AddressID int IDENTITY PRIMARY KEY NOT NULL,
UserID int FOREIGN KEY REFERENCES Users (UserID) NOT NULL,
FirstName nvarchar(30) NOT NULL,
LastName nvarchar(30) NOT NULL,
AddressLine1 nvarchar(100) NOT NULL,
AddressLine2 nvarchar(100),
City nvarchar(60) NOT NULL,
CountryCode int FOREIGN KEY REFERENCES Countries (CountryCode) NOT NULL,
ZipCode nvarchar(20),
PhoneNumber nvarchar(20)
)
GO

CREATE TABLE ShipsToTypes
(
ShipsToTypeCode int IDENTITY PRIMARY KEY,
ShipsToTypeName nvarchar(30)
)
GO

CREATE TABLE Products
(
ProductID int IDENTITY PRIMARY KEY NOT NULL,
UserID int FOREIGN KEY REFERENCES Users (UserID) NOT NULL,
CategoryCode int FOREIGN KEY REFERENCES Categories (CategoryCode),
SubCategoryCode int FOREIGN KEY REFERENCES SubCategories (SubCategoryCode),
ConditionCode int FOREIGN KEY REFERENCES Conditions (ConditionCode) NOT NULL,
ProductName nvarchar(80) NOT NULL,
Price float,
SellTypeCode int FOREIGN KEY REFERENCES SellTypes (SellTypeCode) NOT NULL,
CountryCode int FOREIGN KEY REFERENCES Countries (CountryCode),
ShipsToTypeCode int FOREIGN KEY REFERENCES ShipsToTypes (ShipsToTypeCode) NOT NULL,
ShippingCosts float,
Description nvarchar(400),
Quantity int NOT NULL,
Size nvarchar(50),
UploadDate datetime NOT NULL,
ImagesSource nvarchar(100),
IsHidden bit NOT NULL
)
GO

CREATE TABLE Cart
(
CartID int FOREIGN KEY REFERENCES Users (UserID) NOT NULL,
ProductID int FOREIGN KEY REFERENCES Products (ProductID) NOT NULL
)
GO

CREATE TABLE Orders
(
OrderID nvarchar(30) PRIMARY KEY NOT NULL,
UserID int FOREIGN KEY REFERENCES Users (UserID) NOT NULL,
FirstName nvarchar(30) NOT NULL,
LastName nvarchar(30) NOT NULL,
AddressLine1 nvarchar(100) NOT NULL,
AddressLine2 nvarchar(100),
City nvarchar(60) NOT NULL,
CountryCode int FOREIGN KEY REFERENCES Countries (CountryCode) NOT NULL,
ZipCode nvarchar(20),
PhoneNumber nvarchar(20),
Total float,
CreatedOn datetime NOT NULL
)
GO

CREATE TABLE OrderItems
(
OrderID nvarchar(30) FOREIGN KEY REFERENCES Orders (OrderID) NOT NULL,
ProductID int FOREIGN KEY REFERENCES Products (ProductID) NOT NULL,
)
GO

CREATE TABLE Chats
(
ChatID int IDENTITY PRIMARY KEY,
UserOneID int FOREIGN KEY REFERENCES Users (UserID),
UserTwoID int FOREIGN KEY REFERENCES Users (UserID),
CreatedOn datetime,
LastReplySentOn datetime
)
GO

CREATE TABLE Replies
(
UserID int FOREIGN KEY REFERENCES Users (UserID),
ChatID int FOREIGN KEY REFERENCES Chats (ChatID),
Reply nvarchar(200),
TimeSent datetime
)
GO


--יצירת פרוצדורות


-- שינוי פורמט תאריך
Set DateFormat dmy
GO


-- הצפנת סיסמא
CREATE PROC HashPass(@pass nvarchar(255), @out varbinary(max) output)
AS
SET @out = HASHBYTES('SHA2_512', @pass)
GO

-- האם אימייל קיים
CREATE PROC DoesEmailExists
(@Email nvarchar(120))
AS
BEGIN
	IF EXISTS(SELECT * FROM Users WHERE Email = @Email)
	BEGIN
		SELECT 'true'
	END
	ELSE
	BEGIN
		SELECT 'false'
	END
END
GO

-- האם השם משתמש קיים
CREATE PROC IsUsernameExists
(@Username nvarchar(120))
AS
BEGIN
	IF EXISTS(SELECT * FROM Users WHERE Username = @Username)
	BEGIN
		SELECT 'true'
	END
	ELSE
	BEGIN
		SELECT 'false'
	END
END
GO


-- הוספת משתמש
CREATE PROC AddUser(
@FirstName nvarchar(30),
@LastName nvarchar(30),
@Username nvarchar(30),
@Email nvarchar(120),
@Password nvarchar(30)
)
AS
BEGIN TRANSACTION
DECLARE @Salt varchar(100)
SET @Salt = CONVERT(varchar(100), NEWID())
DECLARE @PassConcat nvarchar(255)
SET @PassConcat = CONCAT(@Password, @Salt)
DECLARE @PasswordHash varbinary(max)
EXEC HashPass @PassConcat, @PasswordHash OUTPUT
INSERT Users(FirstName, LastName, Username, Email, PasswordHash, PasswordSalt)
VALUES (@FirstName, @LastName, @Username, @Email, @PasswordHash, @Salt)
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- קבלת סיסמא מוצפנת
CREATE PROC GetHash (
@Password nvarchar(30),
@PasswordSalt nvarchar(100),
@Result varbinary(max) OUTPUT
)
AS
SELECT @Result = HASHBYTES('SHA2_512', CONCAT(@Password, @PasswordSalt))
GO


-- אימות משתמש
CREATE PROC ValidateUser
(
@Email nvarchar(120),
@Password nvarchar(130),
@Result int OUTPUT
)
AS
DECLARE @PassSalt nvarchar(100)
SELECT @PassSalt = PasswordSalt FROM Users WHERE Email = @Email
DECLARE @PassHash varbinary(max)
EXEC GetHash @Password, @PassSalt, @PassHash OUTPUT  -- מקבל את ההצפנה של הסיסמא שהתבקלה
IF ((SELECT PasswordHash FROM Users WHERE Email = @Email) = @PassHash)
BEGIN
SELECT @Result = UserID FROM Users WHERE Email = @Email AND PasswordHash = @PassHash
END
ELSE
BEGIN
SET @Result = 0
END
GO


--ID הצגת משתמש לפי
CREATE PROC GetUserById(@UserID int)
AS
SELECT UserID, FirstName, LastName, Username, Email FROM Users WHERE UserID = @UserID
GO


-- קבלת שם משתמש לפי מזהה של משתמש
CREATE PROC GetUsernameById
(
@UserID int
)
AS
SELECT Username FROM Users
WHERE UserID = @UserID
GO


--עדכון פרטי משתמש
CREATE PROC EditUserInfo
(
@UserID int,
@FirstName nvarchar(30),
@LastName nvarchar(30),
@Username nvarchar(30),
@Email nvarchar(120)
)
AS
BEGIN TRANSACTION
UPDATE Users
SET FirstName = @FirstName, 
LastName = @LastName,
Username = @Username,
Email = @Email
WHERE UserID = @UserID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- האם הסיסמא החדשה שונה מהסיסמא הקיימת
CREATE PROC IsCurrentPasswordTheSame
(
@UserID int,
@Password nvarchar(16)
)
AS
BEGIN TRANSACTION
DECLARE @PassSalt nvarchar(100)
SELECT @PassSalt = PasswordSalt FROM Users WHERE UserID = @UserID
DECLARE @PassHash varbinary(max)
EXEC GetHash @Password, @PassSalt, @PassHash OUTPUT
IF ((SELECT PasswordHash FROM Users WHERE UserID = @UserID) = @PassHash)
BEGIN
SELECT 'true'
END
ELSE
BEGIN
SELECT 'false'
END
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- מחזיר את המזהה של המשתמש לפי האימייל
CREATE PROC GetUserIDByEmail
(
@Email nvarchar(120)
)
AS
SELECT UserID FROM Users WHERE Email=@Email
GO


-- שנה סיסמא
CREATE PROC ChangePassword
(
@UserID int,
@Password nvarchar(16)
)
AS
BEGIN TRANSACTION
DECLARE @PassSalt nvarchar(100)
SELECT @PassSalt = PasswordSalt FROM Users WHERE UserID = @UserID
DECLARE @PassHash varbinary(max)
EXEC GetHash @Password, @PassSalt, @PassHash OUTPUT
UPDATE Users
SET PasswordHash = @PassHash
WHERE UserID = @UserID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--יצירת צאט
CREATE PROC CreateChat
(
@UserOneID int,
@UserTwoID int
)
AS
BEGIN TRANSACTION
IF EXISTS(SELECT ChatID FROM Chats WHERE UserOneID = @UserOneID AND UserTwoID = @UserTwoID)
BEGIN
SELECT 0
END
ELSE BEGIN
INSERT Chats(UserOneID, UserTwoID, CreatedOn) 
VALUES (@UserOneID, @UserTwoID, GETDATE())
END
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--מחיקת צאט
CREATE PROC DeleteChat
(
@ChatID int
)
AS
BEGIN TRANSACTION
DELETE FROM Replies WHERE ChatID = @ChatID
DELETE FROM Chats WHERE ChatID = @ChatID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--שליחת הודעה
CREATE PROC SendMessage
(
@UserID int,
@ChatID int,
@Reply nvarchar(200)
)
AS
BEGIN TRANSACTION
INSERT Replies(UserID, ChatID, Reply, TimeSent)
VALUES (@UserID, @ChatID, @Reply, GETDATE())
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- מחזיר את כל הצאטים שהמשתמש נוכח בהם
CREATE PROC GetAllChatsByUserID
(
@UserID int
)
AS
BEGIN TRANSACTION
SELECT * FROM Chats WHERE UserOneID = @UserID OR UserTwoID = @UserID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- מחזיר את כל ההודעות בצאט לפי מזהה של צאט
CREATE PROC GetAllRepliesByChatID
(
@ChatID int
)
AS
BEGIN TRANSACTION
SELECT * FROM Replies WHERE ChatID = @ChatID
ORDER BY TimeSent
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- בודק אם קיים צאט כבר
CREATE PROC DoesChatExists
(
@ChatID int,
@UserOneID int,
@UserTwoID int
)
AS
BEGIN TRANSACTION
SELECT ChatID FROM Chats WHERE ChatID = @ChatID AND (UserOneID = @UserOneID AND UserTwoID = @UserTwoID)
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- מחזיר את המזהה של הצאט לפי המשתתפים
CREATE PROC GetChatID
(
@UserOneID int,
@UserTwoID int
)
AS
BEGIN TRANSACTION
IF EXISTS(SELECT ChatID FROM Chats WHERE UserOneID = @UserOneID AND UserTwoID = @UserTwoID)
BEGIN
	SELECT ChatID FROM Chats WHERE UserOneID = @UserOneID AND UserTwoID = @UserTwoID
END
ELSE BEGIN
	SELECT -1
END
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--הוספת כתובת למשתמש
CREATE PROC AddAddress
(
@UserID int,
@FirstName nvarchar(30),
@LastName nvarchar(30),
@AddressLine1 nvarchar(100),
@AddressLine2 nvarchar(100),
@City nvarchar(60),
@CountryCode int,
@ZipCode nvarchar(20),
@PhoneNumber nvarchar(20)
)
AS
BEGIN TRANSACTION
INSERT UserAddresses(UserID, FirstName, LastName, AddressLine1, AddressLine2, City, CountryCode, ZipCode, PhoneNumber)
VALUES (@UserID, @FirstName, @LastName, @AddressLine1, @AddressLine2, @City, @CountryCode, @ZipCode, @PhoneNumber)
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--מחיקת כתובת
CREATE PROC DeleteAddress
(
@AddressID int
)
AS
BEGIN TRANSACTION
DELETE FROM UserAddresses WHERE AddressID = @AddressID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- הצגת כתובות לפי מזהה של משתמש
CREATE PROC GetAddressesByUserId
(@UserID int)
AS
SELECT * FROM UserAddresses WHERE UserID = @UserID
GO

--עדכון פרטי כתובת
CREATE PROC EditAddress
(
@AddressID int,
@FirstName nvarchar(30),
@LastName nvarchar(30),
@AddressLine1 nvarchar(100),
@AddressLine2 nvarchar(100),
@City nvarchar(60),
@CountryCode int,
@ZipCode nvarchar(20),
@PhoneNumber nvarchar(20)
)
AS
BEGIN TRANSACTION
UPDATE UserAddresses
SET FirstName = @FirstName, 
LastName = @LastName,
AddressLine1 = @AddressLine1,
AddressLine2 = @AddressLine2,
City = @City,
CountryCode = @CountryCode,
ZipCode = @ZipCode,
PhoneNumber = @PhoneNumber
WHERE AddressID = @AddressID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- הוספת מוצר
CREATE PROC AddProduct
(
@UserID int,
@CategoryCode int,
@SubCategoryCode int,
@ConditionCode int,
@ProductName nvarchar(80),
@Price float,
@SellTypeCode int,
@CountryCode int,
@ShipsToTypeCode int,
@ShippingCosts float,
@Description nvarchar(400),
@Quantity int,
@Size nvarchar(50),
@ImagesSource nvarchar(100)
)
AS
BEGIN TRANSACTION
INSERT Products(UserID, CategoryCode, SubCategoryCode, ConditionCode, ProductName, Price, SellTypeCode, CountryCode, ShipsToTypeCode, ShippingCosts, Description, Quantity, Size, UploadDate, ImagesSource, IsHidden)
VALUES (@UserID, @CategoryCode, @SubCategoryCode, @ConditionCode, @ProductName, @Price, @SellTypeCode, @CountryCode, @ShipsToTypeCode, @ShippingCosts, @Description, @Quantity, @Size, GETDATE(), @ImagesSource, 0)
DECLARE @IdentityCode int
SET @IdentityCode = SCOPE_IDENTITY()
COMMIT TRANSACTION
RETURN @IdentityCode
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- ערוך מוצר
CREATE PROC EditProduct
(
@ProductID int,
@CategoryCode int,
@SubCategoryCode int,
@ConditionCode int,
@ProductName nvarchar(80),
@Price float,
@SellTypeCode int,
@CountryCode int,
@ShipsToTypeCode int,
@ShippingCosts float,
@Description nvarchar(400),
@Quantity int,
@Size nvarchar(50),
@ImagesSource nvarchar(100)
)
AS
BEGIN TRANSACTION
UPDATE Products SET CategoryCode = @CategoryCode,
SubCategoryCode = @SubCategoryCode,
ConditionCode = @ConditionCode,
ProductName = @ProductName,
Price = @Price,
SellTypeCode = @SellTypeCode,
CountryCode = @CountryCode,
ShipsToTypeCode = @ShipsToTypeCode,
ShippingCosts = @ShippingCosts,
Description = @Description,
Quantity = @Quantity,
Size = @Size,
ImagesSource = @ImagesSource
WHERE ProductID = @ProductID
COMMIT TRANSACTION
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
GO


-- עריכת מקור תמונות
CREATE PROC EditProductImagesSource(
@ProductID int,
@ImagesSource nvarchar(100)
)
AS
BEGIN TRANSACTION
UPDATE Products
SET ImagesSource = @ImagesSource
WHERE ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--עריכת מחיר מוצר
CREATE PROC EditProductPrice
(
@ProductID int,
@Price float
)
AS
BEGIN TRANSACTION
UPDATE Products SET Price = @Price
WHERE ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- מחיקת מוצר
CREATE PROC DeleteProduct
(
@ProductID int
)
AS
BEGIN TRANSACTION
UPDATE Products
SET IsHidden = 1
WHERE ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- הצגת המוצר לפי המזהה
CREATE PROC GetProductById
(
@ProductID int
)
AS
SELECT * FROM Products WHERE ProductID = @ProductID
GO


--הוספת מוצר לעגלה
CREATE PROC AddToCart
(
@CartID int,
@ProductID int
)
AS
BEGIN TRANSACTION
IF ((SELECT COUNT(ProductID) FROM Cart WHERE CartID = @CartID AND ProductID = @ProductID) = 0)
BEGIN
	INSERT Cart(CartID, ProductID) VALUES (@CartID, @ProductID)
	IF @@ERROR<>0
	BEGIN
		ROLLBACK TRANSACTION
		PRINT(@@ERROR)
		RETURN
	END
END
COMMIT TRANSACTION
GO


--מחיקה מעגלה
CREATE PROC RemoveFromCart
(
@CartID int,
@ProductID int
)
AS
BEGIN TRANSACTION
DELETE FROM Cart WHERE CartID = @CartID AND ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- הצגת פריטים בעגלה לפי מזהה משתמש
CREATE PROC GetCartItemsByUserID
(
@CartID int
)
AS
BEGIN TRANSACTION
SELECT Products.ProductID, UserID, CategoryCode, SubCategoryCode, ConditionCode,
ProductName, Price, SellTypeCode, CountryCode, ShipsToTypeCode,
ShippingCosts, Description, Quantity, Size, UploadDate,
ImagesSource, IsHidden FROM Products INNER JOIN Cart ON Cart.ProductID = Products.ProductID WHERE CartID = @CartID AND IsHidden = 0
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--יצירת הזמנה
CREATE PROC MakeOrder
(
@OrderID nvarchar(30),
@UserID int,
@AddressID int,
@Total float
)
AS
BEGIN TRANSACTION
DECLARE @FirstName nvarchar(30)
SELECT @FirstName = FirstName FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @LastName nvarchar(30)
SELECT @LastName = LastName FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @AddressLine1 nvarchar(100)
SELECT @AddressLine1 = AddressLine1 FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @AddressLine2 nvarchar(100)
SELECT @AddressLine2 = AddressLine2 FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @City nvarchar(60)
SELECT @City = City FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @CountryCode int
SELECT @CountryCode = CountryCode FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @ZipCode nvarchar(20)
SELECT @ZipCode = ZipCode FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @PhoneNumber nvarchar(20)
SELECT @PhoneNumber = PhoneNumber FROM UserAddresses WHERE AddressID = @AddressID
INSERT Orders(OrderID, UserID, FirstName, LastName, AddressLine1, AddressLine2, City, CountryCode, ZipCode, PhoneNumber, Total, CreatedOn)
VALUES (@OrderID, @UserID, @FirstName, @LastName, @AddressLine1, @AddressLine2, @City, @CountryCode, @ZipCode, @PhoneNumber, @Total, GETDATE())
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- ניקוי עגלה אחרי שההזמנה שולמה בהצלחה
CREATE PROC ClearUserCart
(
@CartID int
)
AS
DELETE FROM Cart WHERE CartID = @CartID
GO


--הוספת מוצר להזמנה
CREATE PROC AddItemToOrder
(
@OrderID nvarchar(30),
@ProductID int
)
AS
BEGIN TRANSACTION
INSERT OrderItems(OrderID, ProductID) VALUES (@OrderID, @ProductID)
UPDATE Products SET IsHidden = 1 WHERE ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--הצגת כל המוצרים בהזמנה לפי מזהה הזמנה
CREATE PROC GetOrderItems
(@OrderID nvarchar(30))
AS
SELECT Orders.OrderID, Products.ProductID, Products.UserID, Products.ProductName, (Products.Price + Products.ShippingCosts) AS 'Total', Products.ImagesSource, Orders.CreatedOn
FROM OrderItems INNER JOIN Orders ON Orders.OrderID = OrderItems.OrderID
INNER JOIN Products ON Products.ProductID = OrderItems.ProductID
WHERE Orders.OrderID = @OrderID
GO


--מחזירה את כל המזהים של ההזמנות לפי מזהה משתמש
CREATE PROC GetUserOrders
(@UserID int)
AS
SELECT * FROM Orders
WHERE UserID = @UserID
GO


--הצגת כל הקטגוריות
CREATE PROC GetAllCategories
AS
SELECT * FROM Categories
ORDER BY CategoryName
GO


--הצגת כל התתי קטגוריות
CREATE PROC GetAllSubCategories
AS
SELECT * FROM SubCategories
ORDER BY SubCategoryName
GO


--הצגת כל המוצרים
CREATE PROC GetAllProducts
AS
SELECT * FROM Products WHERE IsHidden = 0
GO


--הצגת כל המוצרים לפי המשתמש שהעלה אותם
CREATE PROC GetUserProducts(@UserID int)
AS
SELECT * FROM Products
WHERE UserID = @UserID AND IsHidden = 0
GO

-- הצגת 5 המוצרים האחרונים שהועלו
CREATE PROC GetLatestProducts
AS
SELECT TOP 5 * FROM Products
WHERE IsHidden = 0
ORDER BY UploadDate DESC
GO


-- הוספת טריגרים


-- מעדכן את הזמן האחרון שנשלחה בו הודעה בצאט מסויים
CREATE TRIGGER T_LastSentMessage
ON Replies FOR INSERT
AS
UPDATE Chats
SET LastReplySentOn = GETDATE()
FROM Replies INNER JOIN inserted
ON Replies.ChatID = inserted.ChatID
WHERE Chats.ChatID = inserted.ChatID
GO


-- Reset Identity Field
DBCC CHECKIDENT ('SubCategories', RESEED, 0)


-- הזנת נתונים לטבלאות

-- כל הקטגוריות
INSERT Categories(CategoryName) VALUES ('Adult') 
INSERT Categories(CategoryName) VALUES ('Antiques & Collectibles') 
INSERT Categories(CategoryName) VALUES ('Apparel') 
INSERT Categories(CategoryName) VALUES ('Arts & Entertainment') 
INSERT Categories(CategoryName) VALUES ('Attractions') 
INSERT Categories(CategoryName) VALUES ('Autos & Vehicles') 
INSERT Categories(CategoryName) VALUES ('Beauty & Fitness') 
INSERT Categories(CategoryName) VALUES ('Books & Literature') 
INSERT Categories(CategoryName) VALUES ('Business & Industrial') 
INSERT Categories(CategoryName) VALUES ('Computers') 
INSERT Categories(CategoryName) VALUES ('Consumer Electronics') 
INSERT Categories(CategoryName) VALUES ('Coupons & Discounts') 
INSERT Categories(CategoryName) VALUES ('Finance') 
INSERT Categories(CategoryName) VALUES ('Firearms & Weapons') 
INSERT Categories(CategoryName) VALUES ('Food & Drink') 
INSERT Categories(CategoryName) VALUES ('Games') 
INSERT Categories(CategoryName) VALUES ('Gifts & Special Events') 
INSERT Categories(CategoryName) VALUES ('Health') 
INSERT Categories(CategoryName) VALUES ('Holidays & Seasonal') 
INSERT Categories(CategoryName) VALUES ('Home & Garden') 
INSERT Categories(CategoryName) VALUES ('Internet') 
INSERT Categories(CategoryName) VALUES ('Jobs & Education') 
INSERT Categories(CategoryName) VALUES ('Legal Services') 
INSERT Categories(CategoryName) VALUES ('Libraries & Museums') 
INSERT Categories(CategoryName) VALUES ('Mass Merchants & Department Stores') 
INSERT Categories(CategoryName) VALUES ('People & Society') 
INSERT Categories(CategoryName) VALUES ('Pets & Animals') 
INSERT Categories(CategoryName) VALUES ('Photo & Video Services') 
INSERT Categories(CategoryName) VALUES ('Safety & Survival') 
INSERT Categories(CategoryName) VALUES ('Science') 
INSERT Categories(CategoryName) VALUES ('Smoking & Vaping') 
INSERT Categories(CategoryName) VALUES ('Sports') 
INSERT Categories(CategoryName) VALUES ('Toys & Hobbies') 
INSERT Categories(CategoryName) VALUES ('Travel') 
INSERT Categories(CategoryName) VALUES ('Wedding')
INSERT Categories(CategoryName) VALUES ('Other')
GO

SELECT * FROM Categories
GO


-- כל התת קטגוריות
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (1, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (2, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Athletic Apparel')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Casual Apparel') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Childrens Clothing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Clothing Accessories') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Costumes') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Eyewear') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Footwear') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Formal Wear') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Headwear') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Mens Clothing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Swimwear') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Undergarments') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Womens Clothing')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Comics & Animation') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Comics & Animation/Anime & Manga') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Comics & Animation/Cartoons') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Comics & Animation/Comics') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Concerts & Music Festivals') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Humor') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Movies') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Classical Music') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Country Music') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Dance & Electronic Music') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Jazz & Blues') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Music Education & Instruction') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Music Equipment & Technology') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Music Reference') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Pop Music') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Radio & Podcast') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Religious Music') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Rock Music') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Music & Audio/Urban & Hip-Hop') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Performing Arts') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Performing Arts/Acting & Theater') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Performing Arts/Circus') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Performing Arts/Dance') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Performing Arts/Magic') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'TV Shows & Programs') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Visual Art & Design') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Visual Art & Design/Architecture') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Visual Art & Design/Art Museums & Galleries') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Visual Art & Design/Design') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Visual Art & Design/Painting') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (5, 'Regional Parks & Gardens') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (5, 'Theme Parks') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (5, 'Zoos Aquariums & Preserves')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (5, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Boats & Watercraft') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Campers & RVs') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Classic Vehicles') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Motor Vehicles') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Motor Vehicles/Electric & Alternative') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Motor Vehicles/Motorcycles & Scooters') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Motor Vehicles/Off-Road') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Motor Vehicles/Trucks & SUVs') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Parts & Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Repair & Maintenance') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Safety') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (6, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Body Art') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Cosmetic Procedures') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Face & Body Care') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Face & Body Care/Hygiene & Toiletries') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Face & Body Care/Make-Up & Cosmetics') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Face & Body Care/Perfumes & Fragrances') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Face & Body Care/Shaving & Hair Removal') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Face & Body Care/Skin & Nail Care') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Fitness') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Hair Care') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Hair Care/Hair Loss') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Spas & Beauty Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Spas & Beauty Services/Massage Therapy') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Weight Loss')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (7, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (8, 'Calendars') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (8, 'Childrens Literature') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (8, 'E-Books') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (8, 'Geographic Reference') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (8, 'Language') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (8, 'Notebooks & Planners') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (8, 'Poetry') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (8, 'Writers Resources') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (8, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Advertising & Marketing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Advertising & Marketing/Public Relations') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Agriculture & Forestry') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Agriculture & Forestry/Agricultural Equipment') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Agriculture & Forestry/Beekeeping') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Agriculture & Forestry/Livestock') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Agriculture & Forestry/Wood & Forestry') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Business Finance') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Business Operations') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Business Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Business Services/Consulting') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Business Services/Corporate Events') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Business Services/E-Commerce Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Business Services/Office Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Business Services/Office Supplies') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Business Services/Writing & Editing Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Chemicals Industry') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Chemicals Industry/Plastics & Polymers') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Construction & Maintenance') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Industrial Materials & Equipment') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Industrial Materials & Equipment/Heavy Machinery') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Mail & Package Delivery') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Manufacturing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Metals & Mining') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Metals & Mining/Precious Metals') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Moving & Relocation') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Packaging') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Pharmaceuticals & Biotech') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Printing & Publishing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Renewable & Alternative Energy') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Retail Equipment & Technology') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (9, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'CAD & CAM') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Computer Hardware') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Computer Hardware/Computer Components') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Computer Hardware/Computer Drives & Storage') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Computer Hardware/Computer Peripherals') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Computer Hardware/Desktop Computers') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Computer Hardware/Laptops & Notebooks') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Computer Security') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Computer Security/Hacking & Cracking') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Electronics & Electrical') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Electronics & Electrical/Electronic Components') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Electronics & Electrical/Power Supplies') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Game Systems & Consoles') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Networking') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Software') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Software/Business & Productivity Software') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Software/Multimedia Software') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (10, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'Audio Equipment') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'Camera & Photo Equipment') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'Car Electronics') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'Drones & RC Aircraft') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'GPS & Navigation') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'Mobile & Wireless') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'Mobile & Wireless/Mobile & Wireless Accessories') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'Mobile & Wireless/Mobile Apps & Add-Ons') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'Mobile & Wireless/Mobile Phones') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'Radio & Communications') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'TV & Video Equipment') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (11, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (12, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (13, 'Accounting & Auditing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (13, 'Investing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (13, 'Investing/Currencies & Foreign Exchange') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (13, 'Investing/Stocks & Bonds') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (13, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (14, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Beverages') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Beverages/Alcoholic Beverages') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Beverages/Coffee & Tea') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Beverages/Juice') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Beverages/Soft Drinks') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food/BBQ & Grilling') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food/Baked Goods & Dessert') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food/Baked Goods & Desserts') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food/Breakfast Foods') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food/Candy & Sweets') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food/Grains & Pasta') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food/Meat & Seafood') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food/Pizza') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food/Snack Foods') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Food/Soups & Stews') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (15, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Arcade & Coin-Op Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Board Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Board Games/Chess & Abstract Strategy Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Board Games/Miniatures & Wargaming') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Card Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Card Games/Collectible Card Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Card Games/Poker & Casino Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Computer & Video Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Computer & Video Games/Shooter Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Computer & Video Games/Simulation Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Computer & Video Games/Sports Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Puzzles & Brainteasers') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Roleplaying Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Table Games') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Table Games/Billiards') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (16, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (17, 'Cards & Greetings') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (17, 'Flowers') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (17, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Aging & Geriatrics') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/AIDS & HIV') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/Allergies') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/Arthritis') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/Cancer') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/Diabetes') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/Ear Nose & Throat') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/Heart & Hypertension') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/Pain Management') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/Respiratory Conditions') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/Skin Conditions') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Conditions/Sleep Disorders') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Health Education & Medical Training') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Medical Devices & Equipment') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Medical Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Medical Services/Physical Therapy') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Mens Health') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Mental Health') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Mental Health/Anxiety & Stress') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Nursing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Nursing/Assisted Living & Long Term Care') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Nutrition') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Nutrition/Special & Restricted Diets') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Nutrition/Vitamins & Supplements') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Occupational Health & Safety') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Oral & Dental Care') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Pharmacy') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Pharmacy/Drugs & Medications') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Reproductive Health') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Social Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Substance Abuse') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Substance Abuse/Drug & Alcohol Testing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Substance Abuse/Drug & Alcohol Treatment') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Vision Care') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Vision Care/Eyeglasses & Contacts') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Womens Health') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (18, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (19, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Bed & Bath') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Bed & Bath/Bathroom') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Cleaning') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Gardening & Landscaping') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'HVAC & Climate Control') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'HVAC & Climate Control/Fireplaces & Stoves') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home & Interior Decor') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Appliances') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Furnishings') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Furnishings/Curtains & Window Treatments') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Furnishings/Kitchen & Dining Furniture') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Furnishings/Lamps & Lighting') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Furnishings/Living Room Furniture') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Furnishings/Rugs & Carpets') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Improvement') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Improvement/Construction & Power Tools') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Improvement/Doors & Windows') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Improvement/Flooring') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Improvement/House Painting & Finishing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Improvement/Plumbing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Safety & Security') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Storage & Shelving') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Home Swimming Pools Saunas & Spas') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Kitchen & Dining') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Kitchen & Dining/Cookware & Diningware') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Kitchen & Dining/Small Kitchen Appliances') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Laundry') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Nursery & Playroom') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Pest Control') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Yard & Patio')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (20, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (21, 'Voice & Video Chat') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (21, 'Web Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (21, 'Web Services/Web Design & Development') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (21, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Business') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education/Colleges & Universities') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education/Distance Learning') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education/Homeschooling') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education/Languages') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education/Legal Education') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education/Primary & Secondary Schooling (K-12)') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education/Standardized & Admissions Tests') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education/Teaching & Classroom Resources') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education/Training & Certification') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Education/Vocational & Continuing Education') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Health') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Jobs') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Jobs/Career Resources & Planning') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Jobs/Job Listings') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Jobs/Resumes & Portfolios')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (22, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (23, 'Visa & Immigration') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (23, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (24, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (25, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Family & Relationships') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Family & Relationships/Family') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Family & Relationships/Marriage') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Family & Relationships/Troubled Relationships') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Kids & Teens') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Politics') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Religion & Belief') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Social Issues & Advocacy') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Social Issues & Advocacy/Charity & Philanthropy') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Social Issues & Advocacy/Green Living & Environmental Issues') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Social Networks') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Subcultures & Niche Interests') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (26, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Animal Products & Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Animal Products & Services/Pet Food & Supplies') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Birds') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Cats') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Dogs') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Exotic Pets') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Fish & Aquaria') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Horses') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Pet Food & Supplies') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Rabbits & Rodents') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Reptiles & Amphibians') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Veterinary & Health') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (27, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (28, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (29, 'Military') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (29, 'Safety') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (29, 'Safety/Law Enforcement') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (29, 'Safety/Rescue & Emergency') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (29, 'Safety/Security Products') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (29, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Astronomy') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Biological Sciences') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Biological Sciences/Neuroscience') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Chemistry') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Computer Science') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Earth Sciences') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Earth Sciences/Geology') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Ecology & Environment') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Engineering & Technology') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Engineering & Technology/Robotics') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Mathematics') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Mathematics/Statistics') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (30, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (31, 'Cannabis') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (31, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Animal Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'College Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Combat Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Combat Sports/Boxing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Combat Sports/Martial Arts') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Combat Sports/Wrestling') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Extreme Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Extreme Sports/Drag & Street Racing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Fantasy Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Individual Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Individual Sports/Cycling') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Individual Sports/Golf') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Individual Sports/Gymnastics') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Individual Sports/Racquet Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Individual Sports/Skate Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Individual Sports/Track & Field') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Motor Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Sporting Goods') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Sporting Goods/Fishing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Sporting Goods/Hiking & Camping') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Sporting Goods/Outdoors') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Sporting Goods/Sports Memorabilia') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Sports Coaching & Training') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports/American Football') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports/Australian Football') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports/Baseball') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports/Basketball') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports/Cheerleading') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports/Cricket') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports/Hockey') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports/Rugby') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports/Soccer') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Team Sports/Volleyball') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Trophies and Awards') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Water Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Water Sports/Surfing') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Water Sports/Swimming') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Winter Sports') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Winter Sports/Ice Skating') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Winter Sports/Skiing & Snowboarding') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (32, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Arts & Crafts') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Arts & Crafts/Fiber & Textile Arts') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Building Toys') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Die-cast & Toy Vehicles') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Dolls') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Drawing & Coloring') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Radio Control & Modeling') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Radio Control & Modeling/Model Trains & Railroads') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Ride-On Toys') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Stuffed Toys') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (33, 'Other')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (34, 'Air Travel') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (34, 'Air Travel/Airport Parking & Transportation') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (34, 'Bags & Luggage') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (34, 'Bus & Rail') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (34, 'Car Rental & Taxi Services') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (34, 'Cruises & Charters') 
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (34, 'Hotels & Accommodations')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (34, 'Other')
GO

SELECT * FROM SubCategories
GO


-- כל המצבי מוצר
INSERT Conditions(ConditionName) VALUES ('New In The Box')
INSERT Conditions(ConditionName) VALUES ('Like New')
INSERT Conditions(ConditionName) VALUES ('Used')
INSERT Conditions(ConditionName) VALUES ('Require Fixing')
INSERT Conditions(ConditionName) VALUES ('Irrelevant')
GO

SELECT * FROM Conditions
GO


-- כל המדינות
INSERT Countries(CountryName) VALUES('Afghanistan')
INSERT Countries(CountryName) VALUES('Åland Islands')
INSERT Countries(CountryName) VALUES('Albania')
INSERT Countries(CountryName) VALUES('Algeria')
INSERT Countries(CountryName) VALUES('American Samoa')
INSERT Countries(CountryName) VALUES('AndorrA')
INSERT Countries(CountryName) VALUES('Angola')
INSERT Countries(CountryName) VALUES('Anguilla')
INSERT Countries(CountryName) VALUES('Antarctica')
INSERT Countries(CountryName) VALUES('Antigua and Barbuda')
INSERT Countries(CountryName) VALUES('Argentina')
INSERT Countries(CountryName) VALUES('Armenia')
INSERT Countries(CountryName) VALUES('Aruba')
INSERT Countries(CountryName) VALUES('Australia')
INSERT Countries(CountryName) VALUES('Austria')
INSERT Countries(CountryName) VALUES('Azerbaijan')
INSERT Countries(CountryName) VALUES('Bahamas')
INSERT Countries(CountryName) VALUES('Bahrain')
INSERT Countries(CountryName) VALUES('Bangladesh')
INSERT Countries(CountryName) VALUES('Barbados')
INSERT Countries(CountryName) VALUES('Belarus')
INSERT Countries(CountryName) VALUES('Belgium')
INSERT Countries(CountryName) VALUES('Belize')
INSERT Countries(CountryName) VALUES('Benin')
INSERT Countries(CountryName) VALUES('Bermuda')
INSERT Countries(CountryName) VALUES('Bhutan')
INSERT Countries(CountryName) VALUES('Bolivia')
INSERT Countries(CountryName) VALUES('Bosnia and Herzegovina')
INSERT Countries(CountryName) VALUES('Botswana')
INSERT Countries(CountryName) VALUES('Bouvet Island')
INSERT Countries(CountryName) VALUES('Brazil')
INSERT Countries(CountryName) VALUES('British Indian Ocean Territory')
INSERT Countries(CountryName) VALUES('Brunei Darussalam')
INSERT Countries(CountryName) VALUES('Bulgaria')
INSERT Countries(CountryName) VALUES('Burkina Faso')
INSERT Countries(CountryName) VALUES('Burundi')
INSERT Countries(CountryName) VALUES('Cambodia')
INSERT Countries(CountryName) VALUES('Cameroon')
INSERT Countries(CountryName) VALUES('Canada')
INSERT Countries(CountryName) VALUES('Cape Verde')
INSERT Countries(CountryName) VALUES('Cayman Islands')
INSERT Countries(CountryName) VALUES('Central African Republic')
INSERT Countries(CountryName) VALUES('Chad')
INSERT Countries(CountryName) VALUES('Chile')
INSERT Countries(CountryName) VALUES('China')
INSERT Countries(CountryName) VALUES('Christmas Island')
INSERT Countries(CountryName) VALUES('Cocos (Keeling) Islands')
INSERT Countries(CountryName) VALUES('Colombia')
INSERT Countries(CountryName) VALUES('Comoros')
INSERT Countries(CountryName) VALUES('Congo')
INSERT Countries(CountryName) VALUES('Congo, The Democratic Republic of the')
INSERT Countries(CountryName) VALUES('Cook Islands')
INSERT Countries(CountryName) VALUES('Costa Rica')
INSERT Countries(CountryName) VALUES('Cote DIvoire')
INSERT Countries(CountryName) VALUES('Croatia')
INSERT Countries(CountryName) VALUES('Cuba')
INSERT Countries(CountryName) VALUES('Cyprus')
INSERT Countries(CountryName) VALUES('Czech Republic')
INSERT Countries(CountryName) VALUES('Denmark')
INSERT Countries(CountryName) VALUES('Djibouti')
INSERT Countries(CountryName) VALUES('Dominica')
INSERT Countries(CountryName) VALUES('Dominican Republic')
INSERT Countries(CountryName) VALUES('Ecuador')
INSERT Countries(CountryName) VALUES('Egypt')
INSERT Countries(CountryName) VALUES('El Salvador')
INSERT Countries(CountryName) VALUES('Equatorial Guinea')
INSERT Countries(CountryName) VALUES('Eritrea')
INSERT Countries(CountryName) VALUES('Estonia')
INSERT Countries(CountryName) VALUES('Ethiopia')
INSERT Countries(CountryName) VALUES('Falkland Islands (Malvinas)')
INSERT Countries(CountryName) VALUES('Faroe Islands')
INSERT Countries(CountryName) VALUES('Fiji')
INSERT Countries(CountryName) VALUES('Finland')
INSERT Countries(CountryName) VALUES('France')
INSERT Countries(CountryName) VALUES('French Guiana')
INSERT Countries(CountryName) VALUES('French Polynesia')
INSERT Countries(CountryName) VALUES('French Southern Territories')
INSERT Countries(CountryName) VALUES('Gabon')
INSERT Countries(CountryName) VALUES('Gambia')
INSERT Countries(CountryName) VALUES('Georgia')
INSERT Countries(CountryName) VALUES('Germany')
INSERT Countries(CountryName) VALUES('Ghana')
INSERT Countries(CountryName) VALUES('Gibraltar')
INSERT Countries(CountryName) VALUES('Greece')
INSERT Countries(CountryName) VALUES('Greenland')
INSERT Countries(CountryName) VALUES('Grenada')
INSERT Countries(CountryName) VALUES('Guadeloupe')
INSERT Countries(CountryName) VALUES('Guam')
INSERT Countries(CountryName) VALUES('Guatemala')
INSERT Countries(CountryName) VALUES('Guernsey')
INSERT Countries(CountryName) VALUES('Guinea')
INSERT Countries(CountryName) VALUES('Guinea-Bissau')
INSERT Countries(CountryName) VALUES('Guyana')
INSERT Countries(CountryName) VALUES('Haiti')
INSERT Countries(CountryName) VALUES('Heard Island and Mcdonald Islands')
INSERT Countries(CountryName) VALUES('Holy See (Vatican City State)')
INSERT Countries(CountryName) VALUES('Honduras')
INSERT Countries(CountryName) VALUES('Hong Kong')
INSERT Countries(CountryName) VALUES('Hungary')
INSERT Countries(CountryName) VALUES('Iceland')
INSERT Countries(CountryName) VALUES('India')
INSERT Countries(CountryName) VALUES('Indonesia')
INSERT Countries(CountryName) VALUES('Iran, Islamic Republic Of')
INSERT Countries(CountryName) VALUES('Iraq')
INSERT Countries(CountryName) VALUES('Ireland')
INSERT Countries(CountryName) VALUES('Isle of Man')
INSERT Countries(CountryName) VALUES('Israel')
INSERT Countries(CountryName) VALUES('Italy')
INSERT Countries(CountryName) VALUES('Jamaica')
INSERT Countries(CountryName) VALUES('Japan')
INSERT Countries(CountryName) VALUES('Jersey')
INSERT Countries(CountryName) VALUES('Jordan')
INSERT Countries(CountryName) VALUES('Kazakhstan')
INSERT Countries(CountryName) VALUES('Kenya')
INSERT Countries(CountryName) VALUES('Kiribati')
INSERT Countries(CountryName) VALUES('Korea, Democratic Peoples Republic of')
INSERT Countries(CountryName) VALUES('Korea, Republic of')
INSERT Countries(CountryName) VALUES('Kuwait')
INSERT Countries(CountryName) VALUES('Kyrgyzstan')
INSERT Countries(CountryName) VALUES('Lao PeopleS Democratic Republic')
INSERT Countries(CountryName) VALUES('Latvia')
INSERT Countries(CountryName) VALUES('Lebanon')
INSERT Countries(CountryName) VALUES('Lesotho')
INSERT Countries(CountryName) VALUES('Liberia')
INSERT Countries(CountryName) VALUES('Libyan Arab Jamahiriya')
INSERT Countries(CountryName) VALUES('Liechtenstein')
INSERT Countries(CountryName) VALUES('Lithuania')
INSERT Countries(CountryName) VALUES('Luxembourg')
INSERT Countries(CountryName) VALUES('Macao')
INSERT Countries(CountryName) VALUES('Macedonia, The Former Yugoslav Republic of')
INSERT Countries(CountryName) VALUES('Madagascar')
INSERT Countries(CountryName) VALUES('Malawi')
INSERT Countries(CountryName) VALUES('Malaysia')
INSERT Countries(CountryName) VALUES('Maldives')
INSERT Countries(CountryName) VALUES('Mali')
INSERT Countries(CountryName) VALUES('Malta')
INSERT Countries(CountryName) VALUES('Marshall Islands')
INSERT Countries(CountryName) VALUES('Martinique')
INSERT Countries(CountryName) VALUES('Mauritania')
INSERT Countries(CountryName) VALUES('Mauritius')
INSERT Countries(CountryName) VALUES('Mayotte')
INSERT Countries(CountryName) VALUES('Mexico')
INSERT Countries(CountryName) VALUES('Micronesia, Federated States of')
INSERT Countries(CountryName) VALUES('Moldova, Republic of')
INSERT Countries(CountryName) VALUES('Monaco')
INSERT Countries(CountryName) VALUES('Mongolia')
INSERT Countries(CountryName) VALUES('Montserrat')
INSERT Countries(CountryName) VALUES('Morocco')
INSERT Countries(CountryName) VALUES('Mozambique')
INSERT Countries(CountryName) VALUES('Myanmar')
INSERT Countries(CountryName) VALUES('Namibia')
INSERT Countries(CountryName) VALUES('Nauru')
INSERT Countries(CountryName) VALUES('Nepal')
INSERT Countries(CountryName) VALUES('Netherlands')
INSERT Countries(CountryName) VALUES('Netherlands Antilles')
INSERT Countries(CountryName) VALUES('New Caledonia')
INSERT Countries(CountryName) VALUES('New Zealand')
INSERT Countries(CountryName) VALUES('Nicaragua')
INSERT Countries(CountryName) VALUES('Niger')
INSERT Countries(CountryName) VALUES('Nigeria')
INSERT Countries(CountryName) VALUES('Niue')
INSERT Countries(CountryName) VALUES('Norfolk Island')
INSERT Countries(CountryName) VALUES('Northern Mariana Islands')
INSERT Countries(CountryName) VALUES('Norway')
INSERT Countries(CountryName) VALUES('Oman')
INSERT Countries(CountryName) VALUES('Pakistan')
INSERT Countries(CountryName) VALUES('Palau')
INSERT Countries(CountryName) VALUES('Palestinian Territory, Occupied')
INSERT Countries(CountryName) VALUES('Panama')
INSERT Countries(CountryName) VALUES('Papua New Guinea')
INSERT Countries(CountryName) VALUES('Paraguay')
INSERT Countries(CountryName) VALUES('Peru')
INSERT Countries(CountryName) VALUES('Philippines')
INSERT Countries(CountryName) VALUES('Pitcairn')
INSERT Countries(CountryName) VALUES('Poland')
INSERT Countries(CountryName) VALUES('Portugal')
INSERT Countries(CountryName) VALUES('Puerto Rico')
INSERT Countries(CountryName) VALUES('Qatar')
INSERT Countries(CountryName) VALUES('Reunion')
INSERT Countries(CountryName) VALUES('Romania')
INSERT Countries(CountryName) VALUES('Russian Federation')
INSERT Countries(CountryName) VALUES('RWANDA')
INSERT Countries(CountryName) VALUES('Saint Helena')
INSERT Countries(CountryName) VALUES('Saint Kitts and Nevis')
INSERT Countries(CountryName) VALUES('Saint Lucia')
INSERT Countries(CountryName) VALUES('Saint Pierre and Miquelon')
INSERT Countries(CountryName) VALUES('Saint Vincent and the Grenadines')
INSERT Countries(CountryName) VALUES('Samoa')
INSERT Countries(CountryName) VALUES('San Marino')
INSERT Countries(CountryName) VALUES('Sao Tome and Principe')
INSERT Countries(CountryName) VALUES('Saudi Arabia')
INSERT Countries(CountryName) VALUES('Senegal')
INSERT Countries(CountryName) VALUES('Serbia and Montenegro')
INSERT Countries(CountryName) VALUES('Seychelles')
INSERT Countries(CountryName) VALUES('Sierra Leone')
INSERT Countries(CountryName) VALUES('Singapore')
INSERT Countries(CountryName) VALUES('Slovakia')
INSERT Countries(CountryName) VALUES('Slovenia')
INSERT Countries(CountryName) VALUES('Solomon Islands')
INSERT Countries(CountryName) VALUES('Somalia')
INSERT Countries(CountryName) VALUES('South Africa')
INSERT Countries(CountryName) VALUES('South Georgia and the South Sandwich Islands')
INSERT Countries(CountryName) VALUES('Spain')
INSERT Countries(CountryName) VALUES('Sri Lanka')
INSERT Countries(CountryName) VALUES('Sudan')
INSERT Countries(CountryName) VALUES('Suriname')
INSERT Countries(CountryName) VALUES('Svalbard and Jan Mayen')
INSERT Countries(CountryName) VALUES('Swaziland')
INSERT Countries(CountryName) VALUES('Sweden')
INSERT Countries(CountryName) VALUES('Switzerland')
INSERT Countries(CountryName) VALUES('Syrian Arab Republic')
INSERT Countries(CountryName) VALUES('Taiwan, Province of China')
INSERT Countries(CountryName) VALUES('Tajikistan')
INSERT Countries(CountryName) VALUES('Tanzania, United Republic of')
INSERT Countries(CountryName) VALUES('Thailand')
INSERT Countries(CountryName) VALUES('Timor-Leste')
INSERT Countries(CountryName) VALUES('Togo')
INSERT Countries(CountryName) VALUES('Tokelau')
INSERT Countries(CountryName) VALUES('Tonga')
INSERT Countries(CountryName) VALUES('Trinidad and Tobago')
INSERT Countries(CountryName) VALUES('Tunisia')
INSERT Countries(CountryName) VALUES('Turkey')
INSERT Countries(CountryName) VALUES('Turkmenistan')
INSERT Countries(CountryName) VALUES('Turks and Caicos Islands')
INSERT Countries(CountryName) VALUES('Tuvalu')
INSERT Countries(CountryName) VALUES('Uganda')
INSERT Countries(CountryName) VALUES('Ukraine')
INSERT Countries(CountryName) VALUES('United Arab Emirates')
INSERT Countries(CountryName) VALUES('United Kingdom')
INSERT Countries(CountryName) VALUES('United States')
INSERT Countries(CountryName) VALUES('United States Minor Outlying Islands')
INSERT Countries(CountryName) VALUES('Uruguay')
INSERT Countries(CountryName) VALUES('Uzbekistan')
INSERT Countries(CountryName) VALUES('Vanuatu')
INSERT Countries(CountryName) VALUES('Venezuela')
INSERT Countries(CountryName) VALUES('Viet Nam')
INSERT Countries(CountryName) VALUES('Virgin Islands, British')
INSERT Countries(CountryName) VALUES('Virgin Islands, U.S.')
INSERT Countries(CountryName) VALUES('Wallis and Futuna')
INSERT Countries(CountryName) VALUES('Western Sahara')
INSERT Countries(CountryName) VALUES('Yemen')
INSERT Countries(CountryName) VALUES('Zambia')
INSERT Countries(CountryName) VALUES('Zimbabwe')
GO

SELECT * FROM Countries
GO


-- כל הסוגי מכירת מוצר
INSERT SellTypes(SellTypeName) VALUES ('Buy Now')
INSERT SellTypes(SellTypeName) VALUES ('Auction')
GO

SELECT * FROM SellTypes
GO


-- כל האופציות לאיזורי משלוח
INSERT ShipsToTypes(ShipsToTypeName) VALUES ('Worldwide')
INSERT ShipsToTypes(ShipsToTypeName) VALUES ('My Country Only')
INSERT ShipsToTypes(ShipsToTypeName) VALUES ('Contact Me')
GO

SELECT * FROM ShipsToTypes
GO


SELECT * FROM Chats


-- DROP ALL TABLES SEQUENCE

--DROP TABLE Replies
--GO
--DROP TABLE Chats
--GO
--DROP TABLE UserAddresses
--GO
--DROP TABLE OrderItems
--GO
--DROP TABLE Orders
--GO
--DROP TABLE Cart
--GO
--DROP TABLE Products
--GO
--DROP TABLE Users
--GO
--DROP TABLE SubCategories
--GO
--DROP TABLE Categories
--GO
--DROP TABLE Conditions
--GO
--DROP TABLE SellTypes
--GO
--DROP TABLE Countries
--GO
--DROP TABLE ShipsToTypes
--GO