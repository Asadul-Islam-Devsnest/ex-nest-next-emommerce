import bcrypt from 'bcrypt';
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  BeforeInsert,
  ManyToMany,
  JoinTable,
} from 'typeorm';
import { Permission } from './permissions/permission.entity';

export enum UserRole {
  SUPER_ADMIN = 'super_admin',
  ADMIN = 'admin',
  USER = 'user',
}

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ type: 'enum', enum: UserRole, default: UserRole.USER })
  role: UserRole;

  @ManyToMany(() => Permission, (permission) => permission.users, {
    cascade: true,
  })
  @JoinTable()
  permissions: Permission[];
  @BeforeInsert()
  async hashPassword() {
    this.password = await bcrypt.hash(this.password, 10);
  }
}
