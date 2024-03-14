<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20240305153637 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE category_food (category_id INT NOT NULL, food_id INT NOT NULL, INDEX IDX_5FA353B012469DE2 (category_id), INDEX IDX_5FA353B0BA8E87C4 (food_id), PRIMARY KEY(category_id, food_id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE category_menu (category_id INT NOT NULL, menu_id INT NOT NULL, INDEX IDX_F69E40D412469DE2 (category_id), INDEX IDX_F69E40D4CCD7E912 (menu_id), PRIMARY KEY(category_id, menu_id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('ALTER TABLE category_food ADD CONSTRAINT FK_5FA353B012469DE2 FOREIGN KEY (category_id) REFERENCES category (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE category_food ADD CONSTRAINT FK_5FA353B0BA8E87C4 FOREIGN KEY (food_id) REFERENCES food (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE category_menu ADD CONSTRAINT FK_F69E40D412469DE2 FOREIGN KEY (category_id) REFERENCES category (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE category_menu ADD CONSTRAINT FK_F69E40D4CCD7E912 FOREIGN KEY (menu_id) REFERENCES menu (id) ON DELETE CASCADE');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE category_food DROP FOREIGN KEY FK_5FA353B012469DE2');
        $this->addSql('ALTER TABLE category_food DROP FOREIGN KEY FK_5FA353B0BA8E87C4');
        $this->addSql('ALTER TABLE category_menu DROP FOREIGN KEY FK_F69E40D412469DE2');
        $this->addSql('ALTER TABLE category_menu DROP FOREIGN KEY FK_F69E40D4CCD7E912');
        $this->addSql('DROP TABLE category_food');
        $this->addSql('DROP TABLE category_menu');
    }
}
